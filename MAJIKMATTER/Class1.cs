using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace D
{
    class Alice
    {
        public static byte[] alicePublicKey;

        public static void Main(string[] args)
        {
            using (ECDiffieHellmanCng alice = new ECDiffieHellmanCng())
            {

                alice.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                alice.HashAlgorithm = CngAlgorithm.Sha256;
                alicePublicKey = alice.PublicKey.ToByteArray();
                Bob bob = new Bob();
                CngKey k = CngKey.Import(bob.bobPublicKey, CngKeyBlobFormat.EccPublicBlob);
                byte[] aliceKey = alice.DeriveKeyMaterial(CngKey.Import(bob.bobPublicKey, CngKeyBlobFormat.EccPublicBlob));
                byte[] encryptedMessage = null;
                byte[] iv = null;
                byte[] plaintext = null;
                Send(aliceKey, "Secret message", out encryptedMessage, out iv);
                plaintext = bob.Receive(encryptedMessage, iv);
                iv = null;
                Console.WriteLine("AliceKey:");
                Console.WriteLine(Convert.ToBase64String(aliceKey));
                Console.WriteLine("BobKey:");
                Console.WriteLine(Convert.ToBase64String(bob.bobKey));
                Console.WriteLine("Alice PUBLIC Key:");
                Console.WriteLine(Convert.ToBase64String(alicePublicKey));
                Console.WriteLine("Bob Public Key:");
                Console.WriteLine(Convert.ToBase64String(bob.bobPublicKey));

                if (!aliceKey.Equals(bob.bobKey))
                { Console.WriteLine("KEYS MATCH"); }else { Console.WriteLine("KEYS DONT MATCH"); }
                Console.ReadLine();
                
            }

        }

        private static void Send(byte[] key, string secretMessage, out byte[] encryptedMessage, out byte[] iv)
        {
            using (Aes aes = new AesCryptoServiceProvider())
            {
                aes.Key = key;
                iv = aes.IV;

                // Encrypt the message
                using (MemoryStream ciphertext = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ciphertext, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] plaintextMessage = Encoding.UTF8.GetBytes(secretMessage);
                    cs.Write(plaintextMessage, 0, plaintextMessage.Length);
                    cs.Close();
                    encryptedMessage = ciphertext.ToArray();
                }
            }
        }

    }
    public class Bob
    {
        public byte[] bobPublicKey;
        public byte[] bobKey;
        public Bob()
        {
            using (ECDiffieHellmanCng bob = new ECDiffieHellmanCng())
            {

                bob.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                bob.HashAlgorithm = CngAlgorithm.Sha256;
                bobPublicKey = bob.PublicKey.ToByteArray();
                bobKey = bob.DeriveKeyMaterial(CngKey.Import(Alice.alicePublicKey, CngKeyBlobFormat.EccPublicBlob));

            }
        }

        public byte[] Receive(byte[] encryptedMessage, byte[] iv)
        {

            using (Aes aes = new AesCryptoServiceProvider())
            {
                aes.Key = bobKey;
                aes.IV = iv;
                // Decrypt the message
                using (MemoryStream plaintext = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(plaintext, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(encryptedMessage, 0, encryptedMessage.Length);
                        cs.Close();
                        String message = Encoding.UTF8.GetString(plaintext.ToArray());
                        Console.WriteLine(message);
                        return plaintext.ToArray();
                    }
                }
            }
        }

    }
}
namespace DHAES
{
    public struct CNG
    {
        public CngKey cngkey;
        public CngKey bcngkey;
        public Byte[] key;
        public Byte[] bkey;
        public Byte[] iv;
        public Byte[] publicKey;
        public Byte[] bpublicKey;        
        public Byte[] encryptedBytes;
        public Byte[] plaintextBytes;        
    }
    
    public class DH
    {
        private CNG cng;
        public DH(CNG c) //return public if no public key, return alicekey if there is bob request from bob
        {
            //if alice
            if (c.publicKey == null) //no alice, make alice
            {
                using (ECDiffieHellmanCng alice = new ECDiffieHellmanCng())
                {
                    alice.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                    alice.HashAlgorithm = CngAlgorithm.Sha256;
                    c.publicKey = alice.PublicKey.ToByteArray();
                    cng = c;
                    return;
                }
            }
            if (c.bpublicKey != null) //pass it key from bob to make alice
            {
                using (ECDiffieHellmanCng alice = new ECDiffieHellmanCng())
                {

                    alice.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                    alice.HashAlgorithm = CngAlgorithm.Sha256;
                    c.publicKey = alice.PublicKey.ToByteArray();
                    //CngKey k = CngKey.Import(c.bpublicKey, CngKeyBlobFormat.EccPublicBlob);
                    c.key = alice.DeriveKeyMaterial(CngKey.Import(c.bpublicKey, CngKeyBlobFormat.EccPublicBlob));
                    c.encryptedBytes = null;
                    c.iv = null;
                    cng = c;
                    return;
                }
            }
            //if bob
            if (c.publicKey != null) //make bob with alic public key, use bob bkey + a.iv to decrypt alice messages
            {
                using (ECDiffieHellmanCng bob = new ECDiffieHellmanCng())
                {
                    bob.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                    bob.HashAlgorithm = CngAlgorithm.Sha256;
                    c.bpublicKey = bob.PublicKey.ToByteArray();
                    c.bkey = bob.DeriveKeyMaterial(CngKey.Import(c.publicKey, CngKeyBlobFormat.EccPublicBlob));
                    cng = c;
                    return;
                }
            }
        }        
        public CNG requestCNG()
        {
            return cng;
        }
        public CNG requestEncryption(CNG c)
        {
            EncryptMessage(c.key, c.plaintextBytes, out c.encryptedBytes, out c.iv);
            return c;
        }
        private void EncryptMessage(Byte[] key, Byte[] plaintextMessage, out Byte[] encryptedMessage, out Byte[] iv)
        {
            using (Aes aes = new AesCryptoServiceProvider())
            {
                aes.Key = key;
                iv = aes.IV;
                using (MemoryStream ciphertext = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ciphertext, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(plaintextMessage, 0, plaintextMessage.Length);
                    cs.Close();
                    encryptedMessage = ciphertext.ToArray();
                }
            }
        }
        public CNG requestDecryption(CNG c) //acting only as bob
        {
            DecryptMessage(out c.plaintextBytes, c.encryptedBytes, c.iv, c.bkey);
            cng = c;
            return c;
        }
        private void DecryptMessage(out Byte[] plaintextBytes, Byte[] encryptedBytes, Byte[] iv, Byte[] bkey)
        {

            using (Aes aes = new AesCryptoServiceProvider())
            {
                aes.Key = bkey;
                aes.IV = iv;
                // Decrypt the message
                using (MemoryStream plaintext = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(plaintext, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(encryptedBytes, 0, encryptedBytes.Length);
                        cs.Close();
                        plaintextBytes = plaintext.ToArray();
                    }
                }
            }
        }

    }
}
