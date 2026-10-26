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
    if be16(&b[policy_end..])? != 0x0010 || be16(&b[policy_end+2..])? != 0x0010 ||
       be16(&b[policy_end+4..])? != 0x0003 || be16(&b[policy_end+6..])? != 0x0010 {
        return Err("TPM ECC params not NIST P-256/null".into());
    }
    let (x, nx) = item(b, policy_end + 8, 32)?;
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
