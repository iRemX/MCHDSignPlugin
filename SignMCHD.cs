using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using CryptoPro.Sharpei.Xml;

namespace EncryptionCore
{
    class SignMCHD
    {

       
        public string SingInit(string source, string thumbprint)
        {
            X509Certificate2Collection found;
            string docPatch = Path.GetTempPath();
            string docName = Guid.NewGuid().ToString();
            string signedDoc = $"{docPatch}/{docName}signed.xml";
 
            X509Store store = new X509Store(StoreLocation.LocalMachine);
            store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
            found = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint.Trim(' '), false);

            if (found.Count == 0)
            {
                store = new X509Store(StoreLocation.CurrentUser);
                store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
                found = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint.Trim(' '), false);
            }

            if (found.Count == 0)
               return "Сертификат не найден.";

            X509Certificate2 Certificate = found[0];

            AsymmetricAlgorithm Key = Certificate.PrivateKey;
            SignXmlFile(source, signedDoc, Key, Certificate);
              
            // Читаем все байты из файла
            byte[] outFileBytes = File.ReadAllBytes(signedDoc);
            // Преобразуем байты в строку Base64
            string base64String = Convert.ToBase64String(outFileBytes);

            if (!File.Exists(source))
                File.Delete(source);
            if (!File.Exists(signedDoc))
                File.Delete(signedDoc);

            return base64String;
        }

        // Подписываем XML файл и сохраняем его в новом файле.
        static void SignXmlFile(string FileName,
            string SignedFileName, AsymmetricAlgorithm Key,
            X509Certificate Certificate)
        {
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            doc.Load(new XmlTextReader(FileName));

            SignedXml signedXml = new SignedXml(doc);
            signedXml.SigningKey = Key;

            Reference reference = new Reference();
            reference.Uri = "";
            reference.DigestMethod = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256";
            // reference.DigestMethod = CPSignedXml.XmlDsigGost3411Url;


            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            // XmlDsigSmevTransform smev = new XmlDsigSmevTransform(); 
            // reference.AddTransform(smev);

            XmlDsigC14NTransform c14 = new XmlDsigC14NTransform();
            reference.AddTransform(c14);
            signedXml.AddReference(reference);

            KeyInfo keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(Certificate));
            signedXml.KeyInfo = keyInfo;
            signedXml.ComputeSignature();

            XmlElement xmlDigitalSignature = signedXml.GetXml();
            doc.DocumentElement.AppendChild(doc.ImportNode(xmlDigitalSignature, true));

            if (doc.FirstChild is XmlDeclaration)
            {
                doc.RemoveChild(doc.FirstChild);
            }

            using (XmlTextWriter xmltw = new XmlTextWriter(SignedFileName,
                new UTF8Encoding(false)))
            {
                xmltw.WriteStartDocument();
                doc.WriteTo(xmltw);
            }
        }
    }
}
