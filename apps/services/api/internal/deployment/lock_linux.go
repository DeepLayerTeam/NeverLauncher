//go:build linux

package deployment

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// InstanceLock удерживает flock файловой системы до остановки всех HTTP/рабочих
// процессов. Файлы блокировок намеренно НИКОГДА не удаляются: удаление
// заблокированного inode позволило бы другому процессу создать и заблокировать новый
// inode по тому же пути.
type InstanceLock struct{ file *os.File }

func Acquire(plan Plan) (*InstanceLock, error) {
	if !plan.SingleInstance {
		return &InstanceLock{}, nil
	}
	path := plan.LockPath
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("Блокировка экземпляра: требуется «абсолютный нормализованный путь»")
	}
	parent := filepath.Dir(path)
	// Никогда не проходите через сегменты-символьные ссылки: иначе два имени
	// могут вести к одному хранилищу или блокировка — за пределы заданного тома.
	current := string(filepath.Separator)
	if parent != "/" {
		parts := splitPath(parent)
		for _, part := range parts {
			current = filepath.Join(current, part)
			st, e := os.Lstat(current)
			if os.IsNotExist(e) {
				if e = os.Mkdir(current, 0700); e == nil {
					st, e = os.Lstat(current)
				}
			}
			if e != nil {
				return nil, fmt.Errorf("Родительский каталог блокировки экземпляра %s: %w", current, e)
			}
			if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
				return nil, fmt.Errorf("Для «родительский каталог блокировки экземпляра» %s требуется: настоящий каталог", current)
			}
		}
	}
	st, err := os.Stat(parent)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0022 != 0 {
		return nil, errors.New("Родительский каталог блокировки экземпляра доступен для записи группе или всем пользователям")
	}
	if plan.requireLocalFS {
		owner, ok := st.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Geteuid()) || st.Mode().Perm()&0077 != 0 {
			return nil, errors.New("production instance lock parent: требуется «принадлежит служебному пользователю и имеет права 0700»")
		}
		var fs syscall.Statfs_t
		if err := syscall.Statfs(parent, &fs); err != nil {
			return nil, err
		}
		switch fs.Type {
		case 0xef53, 0x58465342, 0x9123683e: // ext4, XFS, Btrfs
		default:
			return nil, fmt.Errorf("Блокировка экземпляра: требуется «проверенная локальная файловая система ext4/XFS/Btrfs, получен тип 0x%x»", fs.Type)
		}
		if fs.Flags&1 != 0 {
			return nil, errors.New("Файловая система блокировки экземпляра доступна только для чтения")
		}
	}
	// O_NOFOLLOW и O_CLOEXEC предотвращают подмену символьной ссылки и наследование
	// дескриптора дочерним процессом.
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, fmt.Errorf("Не удалось открыть блокировку экземпляра: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	fail := func(e error) (*InstanceLock, error) { _ = file.Close(); return nil, e }
	info, err := file.Stat()
	if err != nil {
		return fail(err)
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 {
		return fail(errors.New("Блокировка экземпляра: требуется «обычный файл владельца с правами 0600 и одной жёсткой ссылкой»"))
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fail(fmt.Errorf("Экземпляр уже запущен, блокировка %s: %w", path, err))
	}
	// Обнаруживайте подмену пути между открытием и получением блокировки.
	pathInfo, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, pathInfo) {
		return fail(errors.New("Путь блокировки экземпляра изменился во время захвата"))
	}
	return &InstanceLock{file: file}, nil
}

func splitPath(path string) []string {
	rel, _ := filepath.Rel("/", path)
	if rel == "." {
		return nil
	}
	sep := string(filepath.Separator)
	var result []string
	for _, piece := range strings.Split(rel, sep) {
		if piece != "" && piece != "." {
			result = append(result, piece)
		}
	}
	return result
}

func (l *InstanceLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	f := l.file
	l.file = nil
	return errors.Join(syscall.Flock(int(f.Fd()), syscall.LOCK_UN), f.Close())
}
