package ru.launcher.sdk.core;

import java.util.*;

/** JSON-парсер без зависимостей с ограничениями ресурсов для управления Extensions. */
public final class Json {
    private Json() {}
    public static Object parse(String input) { return parse(input, 1_048_576); }
    // Более высокий предел нужен только аутентифицированному транспорту событий и
    // хуков. RPC, ответы хоста и разбор манифеста расширения сохраняют исходный предел
    // 1 МиБ.
    static Object parse(String input, int maxChars) {
        if (maxChars < 1 || maxChars > 2_097_152) throw new IllegalArgumentException("Недопустимое ограничение JSON-парсера");
        if (input == null || input.length() > maxChars) throw new IllegalArgumentException("Размер входного JSON превышает ограничение транспорта");
        Reader p = new Reader(input);
        Object result = p.value(0);
        p.white();
        if (p.i != input.length()) throw new IllegalArgumentException("Лишние данные после JSON в позиции " + p.i);
        return result;
    }
    @SuppressWarnings("unchecked")
    public static Map<String,Object> object(Object value) {
        if (!(value instanceof Map<?,?>)) throw new IllegalArgumentException("Ожидается объект JSON");
        return (Map<String,Object>) value;
    }
    public static String string(Map<String,Object> map, String key, boolean required) {
        Object v = map.get(key);
        if (v == null && !required) return "";
        if (!(v instanceof String s) || (required && s.isBlank())) throw new IllegalArgumentException("Недопустимое поле: " + key);
        return s;
    }
    public static String encode(Object obj) {
        StringBuilder out = new StringBuilder();
        write(out, obj, 0);
        return out.toString();
    }
    private static void write(StringBuilder out, Object v, int depth) {
        if (depth > 64) throw new IllegalArgumentException("Глубина JSON превышает ограничение");
        if (v == null) out.append("null");
        else if (v instanceof String s) {
            out.append('"');
            for (int i=0;i<s.length();i++) { char c=s.charAt(i); switch(c) {
                case '"' -> out.append("\\\""); case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n"); case '\r' -> out.append("\\r"); case '\t' -> out.append("\\t");
                default -> { if (c<32) out.append(String.format("\\u%04x", (int)c)); else out.append(c); }
            }} out.append('"');
        } else if (v instanceof Boolean || v instanceof Number) out.append(v);
        else if (v instanceof Map<?,?> map) {
            out.append('{'); boolean first=true;
            for (Map.Entry<?,?> e : map.entrySet()) { if (!(e.getKey() instanceof String)) throw new IllegalArgumentException("Ключи объекта должны быть строками");
                if (!first) out.append(','); first=false; write(out,e.getKey(),depth+1); out.append(':'); write(out,e.getValue(),depth+1); }
            out.append('}');
        } else if (v instanceof Iterable<?> list) {
            out.append('['); boolean first=true; for (Object item:list) { if (!first) out.append(','); first=false; write(out,item,depth+1); } out.append(']');
        } else throw new IllegalArgumentException("Данные не являются JSON: " + v.getClass());
    }
    private static final class Reader {
        final String s; int i; int nodes;
        Reader(String s) { this.s=s; }
        void white() { while (i<s.length() && (s.charAt(i)==' '||s.charAt(i)=='\n'||s.charAt(i)=='\t'||s.charAt(i)=='\r')) i++; }
        char next() { if (i>=s.length()) throw err("Неожиданное значение: «end»"); return s.charAt(i++); }
        IllegalArgumentException err(String m) { return new IllegalArgumentException(m+" at " + i); }
        Object value(int depth) {
            if (depth>64 || ++nodes>100_000) throw err("JSON nesting/size limit");
            white(); if(i>=s.length())throw err("Отсутствует: «value»");
            char c=s.charAt(i);
            if(c=='{') { i++; white(); Map<String,Object> m=new LinkedHashMap<>(); if(i<s.length()&&s.charAt(i)=='}') {i++;return m;}
                while(true) {white(); if(i>=s.length()||s.charAt(i)!='"')throw err("Ожидался ключ"); String k=str(); white(); if(next()!=':')throw err("Ожидалось двоеточие");
                    Object v=value(depth+1); if(m.containsKey(k))throw err("Обнаружен дубликат: ключ"+k);m.put(k,v);
                    white();char sep=next();if(sep=='}')break;if(sep!=',')throw err("Ожидалась запятая");} return m; }
            if(c=='[') {i++;white();List<Object> a=new ArrayList<>();if(i<s.length()&&s.charAt(i)==']'){i++;return a;}
                while(true){a.add(value(depth+1));white();char sep=next();if(sep==']')break;if(sep!=',')throw err("Ожидалась запятая");}return a;}
            if(c=='"')return str();
            if(s.startsWith("true",i)){i+=4;return true;} if(s.startsWith("false",i)){i+=5;return false;} if(s.startsWith("null",i)){i+=4;return null;}
            int start=i; if(c=='-')i++;if(i>=s.length())throw err("number");
            if(s.charAt(i)=='0')i++;else {if(!digit(s.charAt(i)))throw err("number");while(i<s.length()&&digit(s.charAt(i)))i++;}
            boolean fraction=false;
            if(i<s.length()&&s.charAt(i)=='.'){fraction=true;i++;if(i>=s.length()||!digit(s.charAt(i)))throw err("fraction");while(i<s.length()&&digit(s.charAt(i)))i++;}
            if(i<s.length()&&(s.charAt(i)=='e'||s.charAt(i)=='E')){fraction=true;i++;if(i<s.length()&&(s.charAt(i)=='+'||s.charAt(i)=='-'))i++;if(i>=s.length()||!digit(s.charAt(i)))throw err("exponent");while(i<s.length()&&digit(s.charAt(i)))i++;}
            try { if(fraction){double n=Double.parseDouble(s.substring(start,i));if(!Double.isFinite(n))throw err("nonfinite number");return n;}return Long.parseLong(s.substring(start,i)); }
            catch(NumberFormatException e){throw err("Некорректное значение: «number»");}
        }
        boolean digit(char c){return c>='0'&&c<='9';}
        String str(){if(next()!='"')throw err("Ожидалась кавычка");StringBuilder b=new StringBuilder();while(i<s.length()) {
            char c=next();if(c=='"')return b.toString();if(c<32)throw err("control in string");if(c!='\\'){b.append(c);continue;}
            switch(next()){case '"'->b.append('"');case '\\'->b.append('\\');case '/'->b.append('/');case 'b'->b.append('\b');case 'f'->b.append('\f');case 'n'->b.append('\n');case 'r'->b.append('\r');case 't'->b.append('\t');
                case 'u'->{if(i+4>s.length())throw err("unicode escape");int cp;try{cp=Integer.parseInt(s.substring(i,i+4),16);}catch(NumberFormatException e){throw err("unicode escape");}i+=4;b.append((char)cp);}default->throw err("Некорректное значение: «escape»");}
            }throw err("unterminated string");}
    }
}
