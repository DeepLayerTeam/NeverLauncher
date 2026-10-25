package pro.gravit.utils;

/** Source-compatible subset of Gravit's Version value used in LauncherModuleInfo. */
public final class Version implements Comparable<Version> {
    public enum Type { DEV, ALPHA, BETA, RC, RELEASE, STABLE, LTS }
    public final int major, minor, patch, build;
    public final Type type;
    public Version(int major,int minor,int patch,int build,Type type) {
        if(major<0||minor<0||patch<0||build<0)throw new IllegalArgumentException("negative version component");
        this.major=major;this.minor=minor;this.patch=patch;this.build=build;this.type=java.util.Objects.requireNonNull(type);
    }
    public Version(int major,int minor,int patch,Type type){this(major,minor,patch,0,type);}
    public String getVersionString(){return major+"."+minor+"."+patch+"."+build;}
    public boolean isLowerThan(Version other){return compareTo(other)<0;}
    public int compareTo(Version other){int c=Integer.compare(major,other.major);if(c!=0)return c;c=Integer.compare(minor,other.minor);if(c!=0)return c;c=Integer.compare(patch,other.patch);if(c!=0)return c;return Integer.compare(build,other.build);}
    @Override public String toString(){return getVersionString();}
}
