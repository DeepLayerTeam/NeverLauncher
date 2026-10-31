package ru.launcher.sdk.core;

import java.math.BigInteger;
import java.util.*;
import java.util.regex.*;

/** Extensions SemVer ordering and constraint matching compatible with the Go resolver. */
public record SemVer(int major, int minor, int patch, List<String> prerelease) implements Comparable<SemVer> {
    private static final Pattern VERSION = Pattern.compile("^v?(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:\\.(0|[1-9][0-9]*))?(?:-([0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*))?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$");
    public SemVer { if(major<0||minor<0||patch<0)throw new IllegalArgumentException("negative SemVer");prerelease=List.copyOf(prerelease); }
    public static SemVer parse(String raw) {
        Matcher m=VERSION.matcher(Objects.requireNonNull(raw,"version").trim());
        if(!m.matches())throw new IllegalArgumentException("invalid SemVer: "+raw);
        try { List<String> pre=m.group(4)==null?List.of():List.of(m.group(4).split("\\."));
            for(String p:pre)if(p.matches("[0-9]+")&&p.length()>1&&p.charAt(0)=='0')throw new IllegalArgumentException("invalid numeric prerelease: "+raw);
            return new SemVer(Integer.parseInt(m.group(1)),Integer.parseInt(m.group(2)),m.group(3)==null?0:Integer.parseInt(m.group(3)),pre);
        }catch(NumberFormatException e){throw new IllegalArgumentException("SemVer segment overflow",e);}
    }
    @Override public int compareTo(SemVer b) {
        for(int x:new int[]{Integer.compare(major,b.major),Integer.compare(minor,b.minor),Integer.compare(patch,b.patch)})if(x!=0)return x;
        if(prerelease.isEmpty())return b.prerelease.isEmpty()?0:1;
        if(b.prerelease.isEmpty())return -1;
        for(int i=0;i<Math.min(prerelease.size(),b.prerelease.size());i++) {
            String a=prerelease.get(i),c=b.prerelease.get(i);boolean na=a.matches("[0-9]+"),nb=c.matches("[0-9]+");
            int result=na&&nb?new BigInteger(a).compareTo(new BigInteger(c)):na?-1:nb?1:a.compareTo(c);
            if(result!=0)return result;
        }
        return Integer.compare(prerelease.size(),b.prerelease.size());
    }
    public boolean matches(String expression) {
        if(expression==null||expression.isBlank())throw new IllegalArgumentException("empty version constraint");
        boolean matched=false;
        for(String alt:expression.split("\\|\\|",-1)) {
            String normalized=alt.trim().replace(',',' ');
            if(normalized.isBlank())throw new IllegalArgumentException("empty range alternative");
            boolean valid=true;
            for(String part:normalized.split("\\s+")) { boolean current=matchToken(part); valid=valid&&current; }
            matched=matched||valid;
        }
        return matched;
    }
    private boolean matchToken(String token) {
        if(token.equals("*")||token.equalsIgnoreCase("x"))return true;
        if(token.matches("(?:[0-9]+\\.){0,2}(?:[xX*])") || token.matches("(?:[0-9]+\\.)?[xX*]\\.[xX*]")) {
            String[] parts=token.split("\\."); int[] values={major,minor,patch};
            for(int i=0;i<parts.length;i++) {
                if(parts[i].equalsIgnoreCase("x")||parts[i].equals("*"))return true;
                if(Integer.parseInt(parts[i])!=values[i])return false;
            }return true;
        }
        String op="="; String value=token;
        for(String candidate:new String[]{">=","<=",">","<","^","~","="})if(token.startsWith(candidate)){op=candidate;value=token.substring(candidate.length());break;}
        String normalized=value.startsWith("v")?value.substring(1):value;
        int dotCount=(int)normalized.split("[-+]",2)[0].chars().filter(c->c=='.').count();
        if(dotCount==0)normalized=normalized.replaceFirst("(?=[+-]|$)",".0.0");
        else if(dotCount==1)normalized=normalized.replaceFirst("(?=[+-]|$)",".0");
        SemVer base=parse(normalized); int compare=compareTo(base);
        return switch(op){
            case "="->compare==0;case ">"->compare>0;case ">="->compare>=0;case "<"->compare<0;case "<="->compare<=0;
            case "^"->{SemVer upper=base.major>0?new SemVer(Math.addExact(base.major,1),0,0,List.of()):base.minor>0?new SemVer(0,Math.addExact(base.minor,1),0,List.of()):new SemVer(0,0,Math.addExact(base.patch,1),List.of());yield compare>=0&&compareTo(upper)<0;}
            case "~"->{SemVer upper=new SemVer(base.major,Math.addExact(base.minor,1),0,List.of());yield compare>=0&&compareTo(upper)<0;}
            default->throw new IllegalArgumentException("unsupported range operator: "+op);
        };
    }
    @Override public String toString(){return major+"."+minor+"."+patch+(prerelease.isEmpty()?"":"-"+String.join(".",prerelease));}
}
