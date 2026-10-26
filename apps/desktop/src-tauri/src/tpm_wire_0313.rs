//! TPM 2.0 command framing for Windows TBS: never fabricate evidence from CNG metadata.
//! All multibyte TPM integers are big-endian. Checked parsing rejects malformed firmware output.

fn be16(b: &[u8]) -> Result<usize, String> {
    if b.len() < 2 { return Err("truncated TPM2B".into()); }
    Ok(u16::from_be_bytes([b[0], b[1]]) as usize)
}
fn be32(b: &[u8]) -> Result<u32, String> {
    if b.len() < 4 { return Err("truncated TPM UINT32".into()); }
    Ok(u32::from_be_bytes([b[0],b[1],b[2],b[3]]))
}
fn item(b: &[u8], offset: usize, max: usize) -> Result<(&[u8], usize), String> {
    let n = be16(b.get(offset..).ok_or("missing TPM2B")?)?;
    if n > max { return Err("oversized TPM2B".into()); }
    let end = offset.checked_add(2).and_then(|v| v.checked_add(n)).ok_or("TPM length overflow")?;
    Ok((b.get(offset..end).ok_or("truncated TPM2B data")?, end))
}

pub fn read_public_command(handle: u32) -> Vec<u8> {
    let mut cmd = Vec::with_capacity(14);
    cmd.extend_from_slice(&0x8001u16.to_be_bytes());
    cmd.extend_from_slice(&14u32.to_be_bytes());
    cmd.extend_from_slice(&0x00000173u32.to_be_bytes()); // TPM_CC_ReadPublic
    cmd.extend_from_slice(&handle.to_be_bytes());
    cmd
}

pub fn certify_command(object: u32, ak: u32, extra: &[u8; 32]) -> Vec<u8> {
    let mut cmd = Vec::with_capacity(100);
    cmd.extend_from_slice(&0x8002u16.to_be_bytes()); // TPM_ST_SESSIONS
    cmd.extend_from_slice(&0u32.to_be_bytes());
    cmd.extend_from_slice(&0x00000148u32.to_be_bytes()); // TPM_CC_Certify
    cmd.extend_from_slice(&object.to_be_bytes());
    cmd.extend_from_slice(&ak.to_be_bytes());
    // Both handles require authorization: empty password sessions only.
    // If the TPM's CNG keys require nonempty authValue or policy session,
    // Windows TBS must reject this command. Never retry with a weaker mode.
    cmd.extend_from_slice(&18u32.to_be_bytes());
    for _ in 0..2 {
        cmd.extend_from_slice(&0x40000009u32.to_be_bytes()); // TPM_RS_PW
        cmd.extend_from_slice(&0u16.to_be_bytes());
        cmd.push(0);
        cmd.extend_from_slice(&0u16.to_be_bytes());
    }
    cmd.extend_from_slice(&32u16.to_be_bytes());
    cmd.extend_from_slice(extra);
    cmd.extend_from_slice(&0x0010u16.to_be_bytes()); // TPM_ALG_NULL: AK default scheme
    let n = cmd.len() as u32;
    cmd[2..6].copy_from_slice(&n.to_be_bytes());
    cmd
}

fn response_parameters(resp: &[u8], expected_sessions: bool) -> Result<&[u8], String> {
    if resp.len() < 10 || resp.len() > 16384 { return Err("invalid TPM response size".into()); }
    let tag = be16(resp)? as u16;
    if be32(&resp[2..])? as usize != resp.len() { return Err("TPM response size mismatch".into()); }
    let rc = be32(&resp[6..])?;
    if rc != 0 { return Err(format!("TPM returned 0x{rc:08x} (key authorization/policy may be required)")); }
    if expected_sessions {
        if tag != 0x8002 || resp.len() < 14 { return Err("expected TPM session response".into()); }
        let param_len = be32(&resp[10..])? as usize;
        let end = 14usize.checked_add(param_len).ok_or("TPM size overflow")?;
        if end > resp.len() { return Err("truncated TPM response parameters".into()); }
        Ok(&resp[14..end])
    } else {
        if tag != 0x8001 { return Err("unexpected TPM no-session response".into()); }
        Ok(&resp[10..])
    }
}

pub fn parse_public_response(resp: &[u8]) -> Result<(Vec<u8>, [u8;65]), String> {
    let params = response_parameters(resp, false)?;
    let (public, end) = item(params, 0, 4096)?;
    let (_, name_end) = item(params, end, 128)?;
    let (_, final_end) = item(params, name_end, 128)?;
    if final_end != params.len() { return Err("trailing ReadPublic bytes".into()); }
    // TPMT_PUBLIC: type, nameAlg, objectAttrs, authPolicy, parameters, unique.
    let b = &public[2..];
    if b.len() < 14 || be16(b)? != 0x0023 || be16(&b[2..])? != 0x000b {
        return Err("device TPM key must be ECC SHA-256".into());
    }
    let attrs = be32(&b[4..])?;
    let required = (1<<1) | (1<<4) | (1<<5) | (1<<18);
    if attrs & required != required { return Err("TPM device key is not fixed TPM-origin signing key".into()); }
    let (_, policy_end) = item(b, 8, 64)?;
    if b.len() < policy_end + 8 { return Err("truncated TPM ECC parameters".into()); }
    if be16(&b[policy_end..])? != 0x0010 {return Err("TPM ECC symmetric must be null".into());}
    let scheme=be16(&b[policy_end+2..])?;
    let curve_offset=if scheme==0x0010 {policy_end+4} else if scheme==0x0018 {
        if be16(&b[policy_end+4..])? != 0x000b {return Err("TPM ECDSA key must use SHA-256".into());}
        policy_end+6
    } else {return Err("unsupported TPM ECC signing scheme".into());};
    if be16(&b[curve_offset..])? != 0x0003 || be16(&b[curve_offset+2..])? != 0x0010 {
        return Err("TPM ECC curve/KDF not NIST P-256/null".into());
    }
    let (x, nx) = item(b, curve_offset+4, 32)?;
    let (y, ny) = item(b, nx, 32)?;
    if x.len() != 34 || y.len() != 34 || ny != b.len() { return Err("invalid TPM P-256 coordinates".into()); }
    let mut sec1 = [0u8; 65]; sec1[0] = 4;
    sec1[1..33].copy_from_slice(&x[2..]); sec1[33..65].copy_from_slice(&y[2..]);
    Ok((public.to_vec(), sec1))
}

pub fn parse_certify_response(resp: &[u8], extra: &[u8;32]) -> Result<(Vec<u8>,Vec<u8>),String> {
    let params = response_parameters(resp, true)?;
    let (attest, offset) = item(params, 0, 4096)?;
    // TPMT_SIGNATURE consists of scheme, hash and a scheme-specific signature.
    let sig = params.get(offset..).ok_or("missing TPM signature")?;
    if sig.len() < 6 || sig.len() > 1024 { return Err("invalid TPM signature size".into()); }
    let scheme = be16(sig)?;
    if !matches!(scheme, 0x0014 | 0x0016 | 0x0018) || be16(&sig[2..])? != 0x000b {
        return Err("unsupported TPM signature scheme/hash".into());
    }
    let (_, after) = item(sig, 4, 512)?;
    if scheme == 0x0018 {
        let (_, final_end) = item(sig, after, 66)?;
        if final_end != sig.len() { return Err("trailing TPM ECDSA signature bytes".into()); }
    } else if after != sig.len() { return Err("trailing TPM RSA signature bytes".into()); }
    let att = &attest[2..];
    if att.len() < 6 || be32(att)? != 0xff544347 || be16(&att[4..])? != 0x8017 {
        return Err("not TPM_ST_ATTEST_CERTIFY".into());
    }
    let (_, signer_end) = item(att, 6, 128)?;
    let (qualifier, _) = item(att, signer_end, 64)?;
    if qualifier.len() != 34 || qualifier[2..] != extra[..] { return Err("TPM certify challenge mismatch".into()); }
    Ok((attest.to_vec(),sig.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn command_frames_two_auth_sessions() {
        let c = certify_command(0x80000000,0x80000001,&[7;32]);
        assert_eq!(be32(&c[2..]).unwrap() as usize,c.len());
        assert_eq!(be32(&c[18..]).unwrap(),18);
        assert_eq!(&c[c.len()-34..c.len()-2], &[7;32]);
    }
    #[test] fn response_rejects_forgery_and_truncation() {
        assert!(parse_certify_response(&[],&[0;32]).is_err());
        let mut r = [0u8;10]; r[..2].copy_from_slice(&0x8001u16.to_be_bytes());
        r[2..6].copy_from_slice(&10u32.to_be_bytes());
        assert!(parse_certify_response(&r,&[0;32]).is_err());
        assert!(parse_public_response(&r).is_err());
    }
}

#[cfg(test)]
mod test_vectors {
    use super::*;
    fn encoded(inner: &[u8]) -> Vec<u8> {
        let mut b=(inner.len() as u16).to_be_bytes().to_vec(); b.extend_from_slice(inner); b
    }
    fn frame(tag: u16, param: &[u8]) -> Vec<u8> {
        let mut b=Vec::new();b.extend_from_slice(&tag.to_be_bytes());
        b.extend_from_slice(&((10+param.len()) as u32).to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());b.extend_from_slice(param);b
    }
    #[test] fn read_public_requires_correct_fixed_p256_properties_and_framing() {
        let x=hex::decode("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296").unwrap();
        let y=hex::decode("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5").unwrap();
        let mut inner=Vec::new();
        inner.extend_from_slice(&0x0023u16.to_be_bytes());inner.extend_from_slice(&0x000bu16.to_be_bytes());
        inner.extend_from_slice(&((1u32<<1)|(1<<4)|(1<<5)|(1<<18)).to_be_bytes());
        inner.extend_from_slice(&0u16.to_be_bytes());
        for p in [0x0010u16,0x0010u16,0x0003u16,0x0010u16] {inner.extend_from_slice(&p.to_be_bytes());}
        inner.extend_from_slice(&encoded(&x));inner.extend_from_slice(&encoded(&y));
        let mut params=encoded(&inner);params.extend_from_slice(&encoded(&[7;34]));params.extend_from_slice(&encoded(&[3;34]));
        let frame=frame(0x8001,&params);
        let (public,point)=parse_public_response(&frame).unwrap();
        assert_eq!(public,encoded(&inner));assert_eq!(&point[1..33],x);
        let mut mutated=frame.clone();mutated[10+2+4]=0;mutated[10+2+5]=0;mutated[10+2+6]=0;mutated[10+2+7]=0;
        assert!(parse_public_response(&mutated).is_err());
        let mut trailing=frame.clone();trailing.push(0);assert!(parse_public_response(&trailing).is_err());
    }
    #[test] fn certify_nonce_and_signature_are_not_optional() {
        let extra=[21u8;32];
        let mut inner=Vec::new();inner.extend_from_slice(&0xff544347u32.to_be_bytes());
        inner.extend_from_slice(&0x8017u16.to_be_bytes());inner.extend_from_slice(&encoded(&[9;34]));
        inner.extend_from_slice(&encoded(&extra));inner.extend_from_slice(&[0u8;25]);
        inner.extend_from_slice(&encoded(&[5;34]));inner.extend_from_slice(&encoded(&[6;34]));
        let mut params=encoded(&inner);params.extend_from_slice(&0x0014u16.to_be_bytes());
        params.extend_from_slice(&0x000bu16.to_be_bytes());params.extend_from_slice(&encoded(&[8;256]));
        let mut content=(params.len() as u32).to_be_bytes().to_vec();content.extend_from_slice(&params);
        let resp=frame(0x8002,&content);
        let (att,sig)=parse_certify_response(&resp,&extra).unwrap();
        assert_eq!(att,encoded(&inner));assert_eq!(sig.len(),262);
        assert!(parse_certify_response(&resp,&[22;32]).is_err());
        let mut bad=resp.clone();bad[6..10].copy_from_slice(&0x98eu32.to_be_bytes());
        assert!(parse_certify_response(&bad,&extra).is_err());
        let mut short=resp;short.truncate(short.len()-1);
        assert!(parse_certify_response(&short,&extra).is_err());
    }
}

#[cfg(test)]
mod linux_signing_scheme_tests_0314 {
    use super::*;
    #[test]
    fn accepts_linux_hardware_enclave_scheme_only_when_sha256() {
        let mut tpmt=Vec::new();
        tpmt.extend_from_slice(&0x0023u16.to_be_bytes());
        tpmt.extend_from_slice(&0x000bu16.to_be_bytes());
        tpmt.extend_from_slice(&((1u32<<1)|(1<<4)|(1<<5)|(1<<18)).to_be_bytes());
        tpmt.extend_from_slice(&[0,0]); // empty authPolicy
        for w in [0x0010u16, 0x0018, 0x000b, 0x0003, 0x0010] {tpmt.extend_from_slice(&w.to_be_bytes());}
        let x=hex::decode("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296").unwrap();
        let y=hex::decode("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5").unwrap();
        for coord in [x,y] {tpmt.extend_from_slice(&32u16.to_be_bytes());tpmt.extend_from_slice(&coord);}
        let mut params=(tpmt.len() as u16).to_be_bytes().to_vec();params.extend_from_slice(&tpmt);
        params.extend_from_slice(&[0,0,0,0]);
        let mut frame=Vec::new();frame.extend_from_slice(&0x8001u16.to_be_bytes());
        frame.extend_from_slice(&((10+params.len()) as u32).to_be_bytes());frame.extend_from_slice(&[0;4]);frame.extend_from_slice(&params);
        assert!(parse_public_response(&frame).is_ok());
        // The hash parameter in the ECC scheme is at TPMT_PUBLIC index 14-15.
        let hash_offset=10+2+2+2+4+2+2+2;
        frame[hash_offset+1]=0x04;
        assert!(parse_public_response(&frame).is_err());
    }
}

// A TPM Quote must contain one SHA-256 bank with the exact PCR selection and
// the caller's 32-byte qualifying nonce. This is a local defensive parser; the
// backend independently validates the signature and PCR digest.
pub fn validate_quote_0315(att: &[u8], sig: &[u8], extra: &[u8;32], indices: &[u8]) -> Result<(),String> {
    if att.len()<2 || be16(att)?+2!=att.len() {return Err("invalid TPM2B Quote length".into());}
    let bytes=&att[2..];
    if bytes.len()<6 || be32(bytes)?!=0xff544347 || be16(&bytes[4..])?!=0x8018 {
        return Err("invalid TPM Quote magic/type".into());
    }
    let (_,pos)=item(bytes,6,128)?;
    let (nonce,mut pos)=item(bytes,pos,64)?;
    if nonce.len()!=34 || &nonce[2..]!=extra {return Err("TPM quote nonce mismatch".into());}
    pos+=25;
    if bytes.len()<pos+4 || be32(&bytes[pos..])?!=1 {return Err("exactly one PCR bank required".into());}
    pos+=4;
    if bytes.len()<pos+6 || be16(&bytes[pos..])?!=0x000b || bytes[pos+2]!=3 {
        return Err("only SHA-256 PCR bank (size=3) supported".into());
    }
    let mut mask=[0u8;3];
    for &i in indices {if i>23 {return Err("invalid PCR index".into());} mask[(i/8) as usize]|=1<<(i%8);}
    if bytes[pos+3..pos+6]!=mask {return Err("quote PCR selection differs from requested selection".into());}
    pos+=6;
    let (digest,end)=item(bytes,pos,64)?;
    if digest.len()!=34 || end!=bytes.len(){return Err("Quote must contain exactly one SHA-256 PCR digest".into());}
    if sig.len()<6 || sig.len()>2048 {return Err("invalid TPM Quote signature".into());}
    Ok(())
}

pub fn quote_command_0315(ak_handle:u32,extra:&[u8;32],indices:&[u8])->Vec<u8>{
    let mut command=Vec::new();
    command.extend_from_slice(&0x8002u16.to_be_bytes());
    command.extend_from_slice(&0u32.to_be_bytes());
    command.extend_from_slice(&0x00000158u32.to_be_bytes()); // TPM_CC_Quote
    command.extend_from_slice(&ak_handle.to_be_bytes());
    command.extend_from_slice(&9u32.to_be_bytes()); // one TPM_RS_PW session
    command.extend_from_slice(&0x40000009u32.to_be_bytes());
    command.extend_from_slice(&0u16.to_be_bytes());command.push(0);command.extend_from_slice(&0u16.to_be_bytes());
    command.extend_from_slice(&32u16.to_be_bytes());command.extend_from_slice(extra);
    command.extend_from_slice(&0x0010u16.to_be_bytes()); // inScheme = TPM_ALG_NULL
    command.extend_from_slice(&1u32.to_be_bytes()); // count=1
    command.extend_from_slice(&0x000bu16.to_be_bytes());
    command.push(3);
    let mut mask=[0u8;3];for &i in indices {mask[(i/8) as usize]|=1<<(i%8);}
    command.extend_from_slice(&mask);
    let n=command.len() as u32;command[2..6].copy_from_slice(&n.to_be_bytes());command
}

pub fn parse_quote_response_0315(reply:&[u8],extra:&[u8;32],indices:&[u8])->Result<(Vec<u8>,Vec<u8>),String>{
    let params=response_parameters(reply,true)?;
    let (att,offset)=item(params,0,4096)?;
    let sig=params.get(offset..).ok_or("missing TPM Quote signature")?;
    validate_quote_0315(att,sig,extra,indices)?;
    Ok((att.to_vec(),sig.to_vec()))
}

pub fn pcr_read_command_0315(indices:&[u8])->Vec<u8>{
    let mut command=Vec::new();
    command.extend_from_slice(&0x8001u16.to_be_bytes());
    command.extend_from_slice(&0u32.to_be_bytes());
    command.extend_from_slice(&0x0000017eu32.to_be_bytes()); // TPM_CC_PCR_Read
    command.extend_from_slice(&1u32.to_be_bytes());
    command.extend_from_slice(&0x000bu16.to_be_bytes());command.push(3);
    let mut mask=[0u8;3];for &i in indices {mask[(i/8) as usize]|=1<<(i%8);}
    command.extend_from_slice(&mask);
    let n=command.len() as u32;command[2..6].copy_from_slice(&n.to_be_bytes());command
}
pub fn parse_pcr_read_response_0315(reply:&[u8],indices:&[u8])->Result<Vec<[u8;32]>,String>{
    let params=response_parameters(reply,false)?;
    if params.len()<4+4+2+1+3+4 {return Err("truncated PCR_Read response".into());}
    let mut pos=4; // pcrUpdateCounter (unsigned; not a trust signal)
    if be32(&params[pos..])?!=1{return Err("PCR_Read returned unsupported bank count".into());}pos+=4;
    if be16(&params[pos..])?!=0x000b || params[pos+2]!=3{return Err("PCR_Read returned unexpected bank".into());}
    let mut mask=[0u8;3];for &i in indices{mask[(i/8) as usize]|=1<<(i%8);}
    if params[pos+3..pos+6]!=mask {return Err("PCR_Read returned partial/wrong selection".into());}pos+=6;
    if be32(&params[pos..])? as usize!=indices.len(){return Err("PCR_Read returned incomplete PCR values".into());}pos+=4;
    let mut out=Vec::new();
    for _ in indices {
        let (value,end)=item(params,pos,32)?;
        if value.len()!=34 {return Err("PCR_Read returned non-SHA256 value".into());}
        let mut x=[0u8;32];x.copy_from_slice(&value[2..]);out.push(x);pos=end;
    }
    if pos!=params.len(){return Err("trailing PCR_Read response data".into());}
    Ok(out)
}
pub fn parse_pcr_selection_0315(selection:&str)->Result<Vec<u8>,String>{
    let text=selection.strip_prefix("sha256:").ok_or("only SHA-256 PCRs supported")?;
    let mut out=Vec::new();
    for value in text.split(',') {
        if value.is_empty() || value.len()>2 || (value.starts_with('0') && value!="0") ||
           !value.bytes().all(|b|b.is_ascii_digit()) {return Err("invalid PCR index".into());}
        let index=value.parse::<u8>().map_err(|_|"invalid PCR index")?;
        if index>23 || out.last().map_or(false,|previous|*previous>=index){return Err("PCR index not strictly increasing 0..23".into());}
        out.push(index);
    }
    if out.is_empty() || out.len()>24{return Err("empty/oversized PCR selection".into());}
    Ok(out)
}


#[cfg(test)]
mod measured_boot_0315_tests {
    use super::*;
    #[test]
    fn quote_and_read_commands_have_complete_frames() {
        let indices=parse_pcr_selection_0315("sha256:0,2,7,11,23").unwrap();
        let q=quote_command_0315(0x80000001,&[7;32],&indices);
        assert_eq!(be16(&q).unwrap(),0x8002);
        assert_eq!(be32(&q[2..]).unwrap() as usize,q.len());
        assert_eq!(be32(&q[6..]).unwrap(),0x158);
        let read=pcr_read_command_0315(&indices);
        assert_eq!(be16(&read).unwrap(),0x8001);
        assert_eq!(be32(&read[2..]).unwrap() as usize,read.len());
        assert_eq!(be32(&read[6..]).unwrap(),0x17e);
        for input in ["", "sha1:0", "sha256:24", "sha256:2,2", "sha256:7,2", "sha256:01", "sha256:0;bad"] {
            assert!(parse_pcr_selection_0315(input).is_err(),"{input}");
        }
    }
    #[test]
    fn forged_quote_and_pcr_read_fail_closed() {
        assert!(validate_quote_0315(&[],&[],&[0;32],&[0]).is_err());
        assert!(parse_quote_response_0315(&[],&[0;32],&[0]).is_err());
        assert!(parse_pcr_read_response_0315(&[],&[0]).is_err());
        let mut r=vec![0u8;10];r[0..2].copy_from_slice(&0x8001u16.to_be_bytes());
        r[2..6].copy_from_slice(&10u32.to_be_bytes());
        assert!(parse_pcr_read_response_0315(&r,&[0]).is_err());
    }
}
