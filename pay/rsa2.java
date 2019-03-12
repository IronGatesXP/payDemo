public static boolean rsaCheckV1(Map<String, String> params, String publicKey, String charset, String signType) throws AlipayApiException {
        String sign = (String)params.get("sign");
        String content = getSignCheckContentV1(params);
        return rsaCheck(content, sign, publicKey, charset, signType);
    }


public static String getSignCheckContentV1(Map<String, String> params) {
        if (params == null) {
            return null;
        } else {
            params.remove("sign");
            params.remove("sign_type");
            StringBuffer content = new StringBuffer();
            List<String> keys = new ArrayList(params.keySet());
            Collections.sort(keys);

            for(int i = 0; i < keys.size(); ++i) {
                String key = (String)keys.get(i);
                String value = (String)params.get(key);
                content.append((i == 0 ? "" : "&") + key + "=" + value);
            }

            return content.toString();
        }
    }

 public static boolean rsaCheck(String content, String sign, String publicKey, String charset, String signType) throws AlipayApiException {
        if ("RSA".equals(signType)) {
            return rsaCheckContent(content, sign, publicKey, charset);
        } else if ("RSA2".equals(signType)) {
            return rsa256CheckContent(content, sign, publicKey, charset);
        } else {
            throw new AlipayApiException("Sign Type is Not Support : signType=" + signType);
        }
    }



public static boolean rsaCheckContent(String content, String sign, String publicKey, String charset) throws AlipayApiException {
        try {
            PublicKey pubKey = getPublicKeyFromX509("RSA", new ByteArrayInputStream(publicKey.getBytes()));
            Signature signature = Signature.getInstance("SHA1WithRSA");
            signature.initVerify(pubKey);
            if (StringUtils.isEmpty(charset)) {
                signature.update(content.getBytes());
            } else {
                signature.update(content.getBytes(charset));
            }

            return signature.verify(Base64.decodeBase64(sign.getBytes()));
        } catch (Exception var6) {
            throw new AlipayApiException("RSAcontent = " + content + ",sign=" + sign + ",charset = " + charset, var6);
        }
    }


public static boolean rsa256CheckContent(String content, String sign, String publicKey, String charset) throws AlipayApiException {
        try {
            PublicKey pubKey = getPublicKeyFromX509("RSA", new ByteArrayInputStream(publicKey.getBytes()));
            Signature signature = Signature.getInstance("SHA256WithRSA");
            signature.initVerify(pubKey);
            if (StringUtils.isEmpty(charset)) {
                signature.update(content.getBytes());
            } else {
                signature.update(content.getBytes(charset));
            }

            return signature.verify(Base64.decodeBase64(sign.getBytes()));
        } catch (Exception var6) {
            throw new AlipayApiException("RSAcontent = " + content + ",sign=" + sign + ",charset = " + charset, var6);
        }
    }


public static PublicKey getPublicKeyFromX509(String algorithm, InputStream ins) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        StringWriter writer = new StringWriter();
        StreamUtil.io(new InputStreamReader(ins), writer);
        byte[] encodedKey = writer.toString().getBytes();
        encodedKey = Base64.decodeBase64(encodedKey);
        return keyFactory.generatePublic(new X509EncodedKeySpec(encodedKey));
    }


public static Signature getInstance(String algorithm)
            throws NoSuchAlgorithmException {
        List<Service> list;
        if (algorithm.equalsIgnoreCase(RSA_SIGNATURE)) {
            list = GetInstance.getServices(rsaIds);
        } else {
            list = GetInstance.getServices("Signature", algorithm);
        }
        Iterator<Service> t = list.iterator();
        if (t.hasNext() == false) {
            throw new NoSuchAlgorithmException
                (algorithm + " Signature not available");
        }
        // try services until we find an Spi or a working Signature subclass
        NoSuchAlgorithmException failure;
        do {
            Service s = t.next();
            if (isSpi(s)) {
                return new Delegate(s, t, algorithm);
            } else {
                // must be a subclass of Signature, disable dynamic selection
                try {
                    Instance instance =
                        GetInstance.getInstance(s, SignatureSpi.class);
                    return getInstance(instance, algorithm);
                } catch (NoSuchAlgorithmException e) {
                    failure = e;
                }
            }
        } while (t.hasNext());
        throw failure;
    }


public final void initVerify(PublicKey publicKey)
            throws InvalidKeyException {
        engineInitVerify(publicKey);
        state = VERIFY;

        if (!skipDebug && pdebug != null) {
            pdebug.println("Signature." + algorithm +
                " verification algorithm from: " + getProviderName());
        }
    }



public final void update(byte[] data, int off, int len)
            throws SignatureException {
        if (state == SIGN || state == VERIFY) {
            if (data == null) {
                throw new IllegalArgumentException("data is null");
            }
            if (off < 0 || len < 0) {
                throw new IllegalArgumentException("off or len is less than 0");
            }
            if (data.length - off < len) {
                throw new IllegalArgumentException
                    ("data too small for specified offset and length");
            }
            engineUpdate(data, off, len);
        } else {
            throw new SignatureException("object not initialized for "
                                         + "signature or verification");
        }
    }


public final void update(ByteBuffer data) throws SignatureException {
        if ((state != SIGN) && (state != VERIFY)) {
            throw new SignatureException("object not initialized for "
                                         + "signature or verification");
        }
        if (data == null) {
            throw new NullPointerException();
        }
        engineUpdate(data);
    }

public final boolean verify(byte[] signature) throws SignatureException {
        if (state == VERIFY) {
            return engineVerify(signature);
        }
        throw new SignatureException("object not initialized for " +
                                     "verification");
    }


protected void engineUpdate(ByteBuffer input) {
        if (input.hasRemaining() == false) {
            return;
        }
        try {
            if (input.hasArray()) {
                byte[] b = input.array();
                int ofs = input.arrayOffset();
                int pos = input.position();
                int lim = input.limit();
                engineUpdate(b, ofs + pos, lim - pos);
                input.position(lim);
            } else {
                int len = input.remaining();
                byte[] b = new byte[JCAUtil.getTempArraySize(len)];
                while (len > 0) {
                    int chunk = Math.min(len, b.length);
                    input.get(b, 0, chunk);
                    engineUpdate(b, 0, chunk);
                    len -= chunk;
                }
            }
        } catch (SignatureException e) {
            // is specified to only occur when the engine is not initialized
            // this case should never occur as it is caught in Signature.java
            throw new ProviderException("update() failed", e);
        }
    }