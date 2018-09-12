using System;
using System.Xml.Serialization;
using Simple.CredentialManager;

namespace RadminCredWrapper
{
    [Serializable]
    public class RadminCredential
    {
        public const string StorageName = "RadminCredWrapper:";
        public const string Filter = "RadminCredWrapper:*";

        public string Name
        {
            get => Target.Substring(StorageName.Length);
            set => Target = $"{StorageName}{value}";
        }
        public string Target { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public PersistenceType PersistenceType { get; set; }
        public CredentialType Type { get; set; }

        public RadminCredential(){ }

        public RadminCredential(Credential credential)
        {
            Target = credential.Target;
            Username = credential.Username;
            Password = credential.Password;
            PersistenceType = credential.PersistenceType;
            Type = credential.Type;
        }
    }
}
