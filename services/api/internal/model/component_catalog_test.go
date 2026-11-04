package model

import (
    "encoding/json"
    "strings"
    "testing"
)

func validSignedV3Catalog0241() Manifest {
    c := NewComponentCatalog0241([]CatalogComponent0241{
        {ID:"performance.sodium",Name:"Sodium & friends",Files:[]string{"mods/sodium.jar","mods/indium.jar"}},
    },1)
    return Manifest{
        SchemaVersion: ManifestSchemaV3,
        ProjectID:"demo",ProfileID:"vanilla",Channel:"stable",Version:"1.0",CreatedAt:"2026-10-20T00:00:00Z",
        ProfileSnapshot:&ProfileSnapshot{SchemaVersion:ProfileSchemaV2,Revision:1,Digest:ProfileDigest(ProfileSpec{ProjectID:"demo",ID:"vanilla",Name:"Vanilla",Loader:"vanilla"}),Spec:ProfileSpec{ProjectID:"demo",ID:"vanilla",Name:"Vanilla",Loader:"vanilla"}},
        ComponentCatalog:&c,
        Files:[]ManifestFile{
            {Path:"mods/sodium.jar",Size:3,SHA256:strings.Repeat("a",64),URL:"https://example.invalid/sodium",Ownership:"optional"},
            {Path:"mods/indium.jar",Size:4,SHA256:strings.Repeat("b",64),URL:"https://example.invalid/indium",Ownership:"optional"},
        },
    }
}
func TestV3CatalogReferenceDigestIdentityAndImmutability0241(t *testing.T) {
    m:=validSignedV3Catalog0241()
    if err:=ValidateManifestSchema(m);err!=nil {t.Fatal(err)}
    if got:=ComponentCatalogDigest0241(m.ComponentCatalog.Components);got!="85f4d294a8028281b667503339bc444bdf5c05ceef31e87fdee87f5cd0c84119" {t.Fatalf("digest mismatch %s",got)}
    raw,err:=json.Marshal(m);if err!=nil {t.Fatal(err)}
    if !strings.Contains(string(raw),`"componentCatalog"`) || !strings.Contains(string(raw),`Sodium \u0026 friends`) {t.Fatalf("Go signed bytes do not cover HTML-safe catalog: %s", raw)}
    var decoded Manifest
    if err=json.Unmarshal(raw,&decoded);err!=nil {t.Fatal(err)}
    if err=ValidateManifestSchema(decoded);err!=nil {t.Fatal(err)}
    next:=decoded
    next.ComponentCatalog = &ComponentCatalog0241{}
    *next.ComponentCatalog=*decoded.ComponentCatalog
    next.ComponentCatalog.Components=append([]CatalogComponent0241(nil),decoded.ComponentCatalog.Components...)
    next.ComponentCatalog.Components[0].Name="evil"
    if err=ValidateManifestSchema(next);err==nil {t.Fatal("tampered catalog accepted")}
    next=decoded;next.ComponentCatalog=&ComponentCatalog0241{};*next.ComponentCatalog=*decoded.ComponentCatalog
    next.ComponentCatalog.Components=append([]CatalogComponent0241(nil),decoded.ComponentCatalog.Components...)
    next.ComponentCatalog.Components[0].Files=[]string{"mods/not-signed.jar"}
    next.ComponentCatalog.Digest=ComponentCatalogDigest0241(next.ComponentCatalog.Components)
    if err=ValidateManifestSchema(next);err==nil {t.Fatal("undeclared component file accepted")}
    next=decoded
    next.Files=append([]ManifestFile(nil),decoded.Files...)
    next.Files[0].Ownership="user-owned"
    if err=ValidateManifestSchema(next);err==nil {t.Fatal("unsafe component ownership accepted")}
    next=decoded
    next.Files=append([]ManifestFile(nil),decoded.Files...)
    next.Files[0].Path="mods/moved.jar"
    if err=ValidateManifestSchema(next);err==nil {t.Fatal("renamed signed component payload accepted")}
    next=decoded
    next.ComponentCatalog=&ComponentCatalog0241{}
    *next.ComponentCatalog=*decoded.ComponentCatalog
    next.ComponentCatalog.Components=[]CatalogComponent0241{decoded.ComponentCatalog.Components[0],decoded.ComponentCatalog.Components[0]}
    next.ComponentCatalog.Digest=ComponentCatalogDigest0241(next.ComponentCatalog.Components)
    if err=ValidateManifestSchema(next);err==nil {t.Fatal("duplicate stable ID accepted")}
    // Profile revision remains pinned across draft catalog edits.
    next=decoded
    newer:=NewComponentCatalog0241(decoded.ComponentCatalog.Components,2)
    next.ComponentCatalog=&newer
    if err=ValidateReleaseManifestTransition(decoded,next);err!=nil {t.Fatalf("legitimate draft revision: %v",err)}
    next.ProfileSnapshot=&ProfileSnapshot{}
    *next.ProfileSnapshot=*decoded.ProfileSnapshot
    next.ProfileSnapshot.Revision++
    if err=ValidateReleaseManifestTransition(decoded,next);err==nil {t.Fatal("profile snapshot rewrite accepted")}
    next=decoded;next.SchemaVersion=ManifestSchemaV2;next.ComponentCatalog=nil
    if err=ValidateReleaseManifestTransition(decoded,next);err==nil {t.Fatal("schema downgrade accepted")}
}
func TestV3RejectsOrphansLegacyComponentsAndUnknownIDs0241(t *testing.T) {
    m:=validSignedV3Catalog0241()
    m.ComponentCatalog=nil
    if ValidateManifestSchema(m)==nil {t.Fatal("missing v3 catalog accepted")}
    m=validSignedV3Catalog0241();m.SchemaVersion=ManifestSchemaV2
    if ValidateManifestSchema(m)==nil {t.Fatal("v3 catalog in v2 accepted")}
    m=validSignedV3Catalog0241();m.ComponentCatalog.Components[0].ID="../escape"
    m.ComponentCatalog.Digest=ComponentCatalogDigest0241(m.ComponentCatalog.Components)
    if ValidateManifestSchema(m)==nil {t.Fatal("unsafe ID accepted")}
    m=validSignedV3Catalog0241();m.ComponentCatalog.Components[0].Files=[]string{"mods/sodium.jar"}
    m.ComponentCatalog.Digest=ComponentCatalogDigest0241(m.ComponentCatalog.Components)
    if ValidateManifestSchema(m)==nil {t.Fatal("orphan optional file accepted")}
}
