using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Xml;
using System.Xml.Serialization;
using Simple.CredentialManager;

namespace RadminCredWrapper
{
    internal static class RadminCredentialsHelper
    {
        private static string GetTarget(string name)
        {
            return $"{RadminCredential.StorageName}{name}";
        }

        internal static IEnumerable<Credential> GetAll()
        {
            return CredentialManager.GetAllCredentials(RadminCredential.Filter);
        }

        internal static NetworkCredential Get(string name)
        {
            return CredentialManager.GetCredentials(GetTarget(name));
        }

        internal static bool Add(string name)
        {
            string target = GetTarget(name);
            string messageText = $"Please enter Radmin user name and password for the '{name}'";
            bool save = false;

            NetworkCredential networkCredential = CredentialManager.PromptForCredentials(target, ref save, messageText, Program.Title);
            if (networkCredential != null)
            {
                return CredentialManager.SaveCredentials(target, networkCredential);
            }

            return false;
        }

        internal static bool Remove(string name)
        {
            return CredentialManager.RemoveCredentials(GetTarget(name));
        }

        internal static void Clear()
        {
            int count = 0;
            int totalCount = 0;

            foreach (var credential in GetAll())
            {
                if (CredentialManager.RemoveCredentials(credential.Target))
                {
                    count++;
                }
                totalCount++;
            }

            if (totalCount > 0)
            {
                MessageBox.Show($"{count} of {totalCount} credentials removed", Program.Title);
            }
            else
            {
                MessageBox.Show($"Credential storage already cleared", Program.Title);
            }
        }

        internal static void List()
        {
            StringBuilder credentialsBuilder = new StringBuilder();
            int totalCount = 0;

            foreach (var credential in GetAll())
            {
                string name = credential.Target.Substring(RadminCredential.StorageName.Length);
                credentialsBuilder.AppendFormat("{0}\n", name);
                totalCount++;
            }

            if (totalCount > 0)
            {
                MessageBox.Show($"Stored credentials:\n{credentialsBuilder.ToString()}", Program.Title);
            }
            else
            {
                MessageBox.Show($"There are no stored credentials", Program.Title);
            }
        }
       
        internal static void Export(string passphrase)
        {
            using (SaveFileDialog saveFileDialog = new SaveFileDialog())
            {
                saveFileDialog.Filter = "Radmin credentials files (*.crdmn)|*.crdmn|All files (*.*)|*.*";
                saveFileDialog.FileName = "RadminCredentials";
                if (saveFileDialog.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        List<RadminCredential> radminCredentials = new List<RadminCredential>();
                        foreach (var credential in GetAll())
                        {
                            radminCredentials.Add(new RadminCredential(credential));
                        }

                        if (radminCredentials.Count > 0)
                        {
                            byte[] key = new byte[32];
                            byte[] salt = new byte[16];
                            byte[] iv = new byte[16];

                            // Generate salt and iv
                            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
                            rngCsp.GetNonZeroBytes(salt);
                            rngCsp.GetNonZeroBytes(iv);

                            // Derive key from passphrase
                            PasswordDeriveBytes pdb = new PasswordDeriveBytes(passphrase, salt, "SHA256", 1000);
                            key = pdb.GetBytes(32);

                            using (var fs = new FileStream(saveFileDialog.FileName, FileMode.Create, FileAccess.Write, FileShare.None))
                            {
                                // Add salt and iv to the begining of encrypted file
                                fs.Write(salt, 0, salt.Length);
                                fs.Write(iv, 0, iv.Length);

                                AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
                                using (var cryptoStream = new CryptoStream(fs, aes.CreateEncryptor(key, iv), CryptoStreamMode.Write))
                                {
                                    BinaryFormatter formatter = new BinaryFormatter();
                                    formatter.Serialize(cryptoStream, radminCredentials);
                                }
                            }
                        }

                        MessageBox.Show($"{radminCredentials.Count} credentials were exported", Program.Title);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Failed to export credentials.\nError message:\n{ex.Message}", Program.Title);
                    }
                }
            }
        }

        internal static void Import(string passphrase)
        {
            using (OpenFileDialog openFileDialog = new OpenFileDialog())
            {
                openFileDialog.Filter = "Radmin credentials files (*.crdmn)|*.crdmn|All files (*.*)|*.*";
                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        List<RadminCredential> radminCredentials = new List<RadminCredential>();

                        byte[] salt = new byte[16];
                        byte[] iv = new byte[16];

                        using (var fs = new FileStream(openFileDialog.FileName, FileMode.Open, FileAccess.Read, FileShare.None))
                        {
                            // Get salt and iv from the encrypted file
                            fs.Read(salt, 0, salt.Length);
                            fs.Read(iv, 0, iv.Length);

                            // Derive key from passphrase
                            PasswordDeriveBytes pdb = new PasswordDeriveBytes(passphrase, salt, "SHA256", 1000);
                            byte[] key = pdb.GetBytes(32);

                            AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
                            using (var cryptoStream = new CryptoStream(fs, aes.CreateDecryptor(key, iv), CryptoStreamMode.Read))
                            {
                                BinaryFormatter formatter = new BinaryFormatter();
                                radminCredentials = (List<RadminCredential>)formatter.Deserialize(cryptoStream);
                            }
                        }

                        foreach (var radminCredential in radminCredentials)
                        {
                            Credential credential = new Credential()
                            {
                                Username = radminCredential.Username,
                                Password = radminCredential.Password,
                                Target = radminCredential.Target,
                                Type = radminCredential.Type,
                                PersistenceType = radminCredential.PersistenceType
                            };
                            credential.Save();
                        }

                        MessageBox.Show($"{radminCredentials.Count} credentials were imported", Program.Title);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Failed to import credentials.\nError message:\n{ex.Message}", Program.Title);
                    }
                }
            }
        }
    }
}
