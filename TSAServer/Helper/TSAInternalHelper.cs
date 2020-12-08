using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using TSAServer.Model;

namespace TSAServer.Helper
{
    public static class TSAInternalHelper
    {
        public static TSAResponse DoGenerateRFC3161TimeStampInternal(TSARequest tsaRequest, TSAProvider providerToUse)
        {
            TSAResponse result;

            string _certificatePath = providerToUse.InternalCertFilePath;
            string _certificatePassword = providerToUse.CertPassword;
            string _certificateAlias = providerToUse.CertAlias;
            string _keyAlias = providerToUse.KeyCertAlias;
            byte[] _hash;
            switch (tsaRequest.DataType)
            {
                case TsaDataTypeEnum.Data:
                    {
                        SHA1 hash = SHA1.Create();
                        _hash = hash.ComputeHash(Encoding.Default.GetBytes(tsaRequest.Data));
                        break;
                    }
                case TsaDataTypeEnum.Hash:
                    _hash = Convert.FromBase64String(tsaRequest.Data);
                    break;
                default:
                    throw new Exception("Undefined DataType.");
            }
            bool hasTimestampRequestPolicy = !string.IsNullOrEmpty(providerToUse.TimestampRequestPolicy);
            result = GetInternalTimeStamp(_hash, _certificatePath, _certificatePassword, _certificateAlias, _keyAlias, hasTimestampRequestPolicy, providerToUse.TimestampRequestPolicy);

            return result;
        }

        // Token: 0x0601474D RID: 83789 RVA: 0x006004F0 File Offset: 0x005FE6F0
        private static TSAResponse GetInternalTimeStamp(byte[] hash, string certificatePath, string certificatePassword, string certificateAlias, string keyAlias, bool hasTimestampRequestPolicy, string timestampRequestPolicy)
        {
            TSAResponse resTS = new TSAResponse();
            TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
            if (hasTimestampRequestPolicy)
            {
                reqGen.SetReqPolicy(timestampRequestPolicy);
            }
            reqGen.SetCertReq(true);
            TimeStampRequest req = reqGen.Generate(TspAlgorithms.Sha1, hash, BigInteger.ValueOf(100L));
            resTS = GetInternalTimeStampFromRequest(req.GetEncoded(), certificatePath, certificatePassword, certificateAlias, keyAlias);
            return resTS;
        }

        // Token: 0x0601474E RID: 83790 RVA: 0x0060057C File Offset: 0x005FE77C
        private static TSAResponse GetInternalTimeStampFromRequest(byte[] timestampRequest, string certificatePath, string certificatePassword, string certificateAlias, string keyAlias)
        {
            TSAResponse resTS = new TSAResponse();
            Pkcs12Store store = new Pkcs12Store();
            FileStream fs = new FileStream(certificatePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            store.Load(fs, certificatePassword.ToCharArray());
            fs.Close();
            if (store.Count > 0)
            {
                Org.BouncyCastle.X509.X509Certificate cert = store.GetCertificate(certificateAlias).Certificate;
                X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
                X509Extensions exts = TbsCertificateStructure.GetInstance(Asn1Object.FromByteArray(cert.GetTbsCertificate())).Extensions;
                foreach (object obj in exts.ExtensionOids)
                {
                    DerObjectIdentifier var = (DerObjectIdentifier)obj;
                    if (var.Id.Equals(X509Extensions.ExtendedKeyUsage.Id))
                    {
                        certGen.CopyAndAddExtension(var.Id, true, cert);
                    }
                    else
                    {
                        certGen.CopyAndAddExtension(var.Id, exts.GetExtension(var).IsCritical, cert);
                    }
                }
                certGen.SetIssuerDN(cert.IssuerDN);
                certGen.SetNotAfter(cert.NotAfter);
                certGen.SetNotBefore(cert.NotBefore);
                certGen.SetPublicKey(cert.GetPublicKey());
                certGen.SetSerialNumber(cert.SerialNumber);
                //certGen.SetSignatureAlgorithm("SHA1WITHRSA");
                certGen.SetSubjectDN(cert.SubjectDN);
                AsymmetricKeyParameter key = store.GetKey(keyAlias).Key;
                ISignatureFactory signatureFactory = new Asn1SignatureFactory("SHA512WITHRSA", key);

                Org.BouncyCastle.X509.X509Certificate cert2 = certGen.Generate(signatureFactory);
                TimeStampRequest req = new TimeStampRequest(timestampRequest);
                TimeStampTokenGenerator tokenGen = new TimeStampTokenGenerator(key, cert2, TspAlgorithms.Sha1, "1.2");
                X509CollectionStoreParameters storeParam = new X509CollectionStoreParameters(new Org.BouncyCastle.X509.X509Certificate[]
                {
                        cert2
                });
                IX509Store certStore = X509StoreFactory.Create("CERTIFICATE/COLLECTION", storeParam);
                tokenGen.SetCertificates(certStore);
                TimeStampResponseGenerator respGen = new TimeStampResponseGenerator(tokenGen, TspAlgorithms.Allowed);
                TimeStampResponse resp = respGen.Generate(req, cert.SerialNumber, DateTime.UtcNow);
                resTS.GeneratedTime = resp.TimeStampToken.TimeStampInfo.GenTime;
                resTS.TimeStampToken = Convert.ToBase64String(resp.TimeStampToken.GetEncoded());
                TSACertificate certField = new TSACertificate();
                certField.Value = Convert.ToBase64String(cert.GetEncoded());
                resTS.Certificates = new List<TSACertificate>
                    {
                        certField
                    };
            }
            return resTS;
        }

    }
}
