using System;
using SBPluginInterfaceLibrary;

namespace EncryptionCore
{
    /// <summary>
    /// Базовый плагин подписания.
    /// </summary>
    public class EncryptionPlugin : IPlugin2, IArchiveEncryptionPlugin, IEncryptionPlugin3
    {
        #region IEncryptionPlugin 

        public bool IsCertificateStorageSupported { get; private set; }

        public bool IsSimpleSignatureVerification { get; set; }

        public bool CanEncrypt { get; private set; }

        public virtual bool CreateSignature(string content, ICertificate createCertificate, out string signature, out string createMsg, ref DateTime createDateTime)
        {
            signature = null;
            createMsg = null;
            createDateTime = DateTime.UtcNow;
            return false;
        }


        public virtual string Decrypt(string source, string password)
        {
            return password;
        }

        public virtual string DecryptWithCertificate(string source)
        {
            return string.Empty;
        }

        public virtual string Encrypt(string source, string password)
        {
            // Вызов метода подписания МЧД.
            var SignCl = new SignMCHD();
            return SignCl.SingInit(source, password);
        }

        public virtual string EncryptWithCertificate(string source, ICertificate certificate)
        {
            return string.Empty;
        }

        public ICertificate GetCertificate()
        {
            return null;
        }

        public ICertificateStorage GetCertificateStorage()
        {
            return null;
        }

        public string Hash(string Source)
        {
            return string.Empty;
        }

        public virtual string GetSessionKey()
        {
            return string.Empty;
        }

        public virtual bool VerifySignature(string content, string signature, out ICertificate verifyCertificate, out string verifyMsg, out DateTime signDate)
        {
            verifyCertificate = null;
            verifyMsg = null;
            signDate = DateTime.MinValue;
            return true;
        }

        #endregion

        #region IEncryptionPlugin2

        public bool CreateSignature2(string content, ICertificate createCertificate, IAdditionalInfoList additionalInfo, out string signature, out string createMsg, ref DateTime createDateTime)
        {
           
            signature = null;
            createMsg = null;
            createDateTime = DateTime.UtcNow;      
            return false;
        }



        public bool VerifySignature2(string content, string signature, out ICertificate verifyCertificate, out string verifyMsg, out DateTime signDate, out IAdditionalInfoList additionalInfo)
        {
            verifyMsg = null;
            signDate = DateTime.Now;
            verifyCertificate = null;
            additionalInfo = null;
            return true;
        }

        #endregion

        #region IEncryptionPlugin3

        public string GetSigningAttributes(ICertificate certificate, string contentHash, DateTime signDate, IAdditionalInfoList additionalInfo)
        {
            return string.Empty;
        }

        public string SignAttributes(ICertificate certificate, string signingAttributes)
        {
            return string.Empty;
        }

        public virtual string BuildSignature(ICertificate certificate, string signingAttributes, string signedAttributes, IAdditionalInfoList additionalInfo)
        {
            return string.Empty;
        }

        public virtual TVerifySignatureResult VerifySignatureByHash(string contentHash, string signature, out ICertificate verifyCertificate, out string verifyMsg, out DateTime signDate, out IAdditionalInfoList additionalInfo)
        {
            verifyCertificate = null;
            verifyMsg = null;
            signDate = DateTime.Now;
            additionalInfo = null;
            return TVerifySignatureResult.vsrError;
        }

        public virtual THashType GetContentHashTypeFromSignature(string signature)
        {
            return THashType.htUnknown;
        }

        public string HashStreamByHashType(object sourceStream, THashType hashType)
        {
            return string.Empty;
        }

        public string HashStreamByCertificate(object sourceStream, ICertificate certificate)
        {
            return string.Empty;
        }

        #endregion

        #region IPlugin2

        public string PlatformVersion { get; protected set; }

        public string Name { get; protected set; }

        public string Title { get; protected set; }

        public string Description { get; protected set; }

        public string CurrentVersion { get; set; }

        public int VersionCount { get; protected set; }

        public virtual string get_Versions(int index)
        {
            return this.CurrentVersion;
        }

        public void GetDefaultSettings(IPluginSettings settings)
        {
        }

        public void Initialize(IPluginSettings settings)
        {
        }

        public virtual void CheckSettings(IPluginSettings settings)
        {
            // Нет настроек, которые надо бы проверить.
        }

        public bool CheckEnvironment()
        {
            return true;
        }

        #endregion

        #region IEncryptionPlugin4

        public virtual TVerifySignatureResult VerifySignatureByHash2(
          string contentHash, string signature, out ISignatureInformation signatureInformation)
        {
            signatureInformation = null;
            return TVerifySignatureResult.vsrSuccess;
        }

        public virtual string AddTimestampToSignature(string contentHash, string signature, out ITimestamp timestamp)
        {
            timestamp = null;
            return string.Empty;
        }

        public void GetDefaultSecuredSettings(IPluginSettings settings)
        {
        }

        #endregion

        #region IArchiveEncryptionPlugin

        public virtual TVerifySignatureResult VerifySignatureByContentStream(object contentStream,
          string signature, out IArchiveSignatureInformation signatureInformation)
        {
            signatureInformation = null;
            return TVerifySignatureResult.vsrSuccess;
        }

        public virtual IAddValidationDataToSignatureOperationResult AddValidationDataToSignature(string сontentHash, string signature,
          bool ocspResponsesRequired, out string signatureWithValidationData)
        {
            signatureWithValidationData = null;
            return null;
        }

        public virtual bool IsArchivalSignature(string signature)
        {
            return false;
        }

        public virtual string AddArchiveTimestampToSignature(object contentStream,
          string signature, out ITimestamp timestamp)
        {
            timestamp = null;
            return string.Empty;
        }

        #endregion

        #region Конструкторы

        /// <summary>
        /// Конструктор.
        /// </summary>
        internal EncryptionPlugin()
        {
            this.PlatformVersion = "7.54";
            this.CanEncrypt = true;
            this.IsCertificateStorageSupported = true;
            this.Name = "{CCBAA607-4B8B-4EF3-886C-E138EE5CEE31}";
            this.Title = "MCHD Encryption Plugin";
            this.Description = "MCHD Encryption Plugin";
            
        }

        #endregion

        #region IEncryptionPlugin5

        public virtual string GetContentHashFromSignature(string signature)
        {
            return string.Empty;
        }

        #endregion
    }
}
