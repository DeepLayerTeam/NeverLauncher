package ru.launcher.sdk.core;

import java.util.*;

/** Fail-closed JSON Schema subset used by runtime events, commands and config.
 * Supported: type, properties, required, additionalProperties, items, enum,
 * minLength, maxLength, minimum, maximum, minItems, maxItems. Unknown keywords
 * are rejected; this is deliberately not an unrestricted JSON Schema engine.
 */
public final class JsonSchema {
    private static final Set<String> KEYS=Set.of("type","properties","required","additionalProperties","items","enum","minLength","maxLength","minimum","maximum","minItems","maxItems");
    private final Map<String,Object> schema;
    public JsonSchema(Map<String,Object> schema){this.schema=Map.copyOf(Objects.requireNonNull(schema));validateSchema(this.schema,0);}
    public static JsonSchema parse(String json){return new JsonSchema(Json.object(Json.parse(json)));}
    public void validate(Object value){validateValue(schema,value,"$",0);}
    private static void validateSchema(Map<String,Object> s,int depth){
        if(depth>24)throw new IllegalArgumentException("schema too deep");
        for(String k:s.keySet())if(!KEYS.contains(k))throw new IllegalArgumentException("unsupported JSON schema keyword: "+k);
        Object type=s.get("type");if(type!=null&&(!(type instanceof String v)||!Set.of("object","array","string","number","integer","boolean","null").contains(v)))throw new IllegalArgumentException("unsupported schema type");
        for(String k:List.of("minLength","maxLength","minItems","maxItems"))if(s.containsKey(k)&&(!(s.get(k) instanceof Number n)||n.longValue()<0||n.doubleValue()!=n.longValue()))throw new IllegalArgumentException("invalid "+k);
        for(String k:List.of("minimum","maximum"))if(s.containsKey(k)&&!(s.get(k) instanceof Number))throw new IllegalArgumentException("invalid "+k);
        if(s.containsKey("additionalProperties")&&!(s.get("additionalProperties") instanceof Boolean))throw new IllegalArgumentException("additionalProperties must be boolean");
        if(s.containsKey("enum")&&!(s.get("enum") instanceof List<?>))throw new IllegalArgumentException("enum must be array");
        if(s.containsKey("required")){if(!(s.get("required") instanceof List<?> keys))throw new IllegalArgumentException("required must be array");for(Object key:keys)if(!(key instanceof String))throw new IllegalArgumentException("required must contain strings");}
        if(s.containsKey("properties")){Map<String,Object> props=Json.object(s.get("properties"));for(Object child:props.values())validateSchema(Json.object(child),depth+1);}
        if(s.containsKey("items"))validateSchema(Json.object(s.get("items")),depth+1);
    }
    private static void validateValue(Map<String,Object> schema,Object v,String path,int depth){
        if(depth>32)throw new IllegalArgumentException("value too deep at "+path);
        String type=(String)schema.get("type");
        if(type!=null){boolean ok=switch(type){case "object"->v instanceof Map<?,?>;case "array"->v instanceof List<?>;case "string"->v instanceof String;case "boolean"->v instanceof Boolean;case "integer"->v instanceof Long||v instanceof Integer;case "number"->v instanceof Number;case "null"->v==null;default->false;};if(!ok)throw new IllegalArgumentException(path+" expects "+type);}
        if(schema.containsKey("enum")&&!((List<?>)schema.get("enum")).contains(v))throw new IllegalArgumentException(path+" is not an allowed value");
        if(v instanceof String s){checkLimit(schema,"minLength",s.codePointCount(0,s.length()),true,path);checkLimit(schema,"maxLength",s.codePointCount(0,s.length()),false,path);}
        if(v instanceof Number n){if(schema.containsKey("minimum")&&n.doubleValue()<((Number)schema.get("minimum")).doubleValue())throw new IllegalArgumentException(path+" below minimum");if(schema.containsKey("maximum")&&n.doubleValue()>((Number)schema.get("maximum")).doubleValue())throw new IllegalArgumentException(path+" above maximum");}
        if(v instanceof List<?> list){checkLimit(schema,"minItems",list.size(),true,path);checkLimit(schema,"maxItems",list.size(),false,path);if(schema.containsKey("items"))for(int i=0;i<list.size();i++)validateValue(Json.object(schema.get("items")),list.get(i),path+"["+i+"]",depth+1);}
        if(v instanceof Map<?,?> map){Map<String,Object> props=schema.containsKey("properties")?Json.object(schema.get("properties")):Map.of();if(schema.containsKey("required"))for(Object key:(List<?>)schema.get("required"))if(!map.containsKey(key))throw new IllegalArgumentException(path+" missing required "+key);for(var e:map.entrySet()){if(!(e.getKey() instanceof String k))throw new IllegalArgumentException("object key not string");if(props.containsKey(k))validateValue(Json.object(props.get(k)),e.getValue(),path+"."+k,depth+1);else if(Boolean.FALSE.equals(schema.get("additionalProperties")))throw new IllegalArgumentException(path+" unknown property "+k);}}
    }
    private static void checkLimit(Map<String,Object> s,String k,int actual,boolean min,String path){if(s.containsKey(k)){long n=((Number)s.get(k)).longValue();if(min?actual<n:actual>n)throw new IllegalArgumentException(path+" violates "+k);}}
}
