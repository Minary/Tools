namespace HttpReverseProxy
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Interface;
  using System;
  using System.Collections.Generic;
  using System.IO;
  using System.Net;
  using System.Net.Security;
  using System.Net.Sockets;
  using System.Reflection;
  using System.Security.Authentication;
  using System.Security.Cryptography.X509Certificates;
  using System.Text;
  using System.Threading;


  public sealed class HttpsReverseProxy : HttpReverseProxyBasis, IPluginHost
  {

    #region MEMBERS

    private static readonly HttpsReverseProxy ReverseProxyServer = new HttpsReverseProxy();
    private static X509Certificate2 serverCertificate2;
    private static RemoteCertificateValidationCallback remoteCertificateValidation = new RemoteCertificateValidationCallback(delegate { return true; });
    private TcpListener tcpListener;
    private Thread tcpListenerThread;
    private Lib.PluginCalls pluginCalls;

    #endregion


    #region PROPERTIES

    public static HttpsReverseProxy Server
    {
      get { return ReverseProxyServer; }
    }

    public IPAddress ListeningIpInterface
    {
      get { return IPAddress.Any; }
    }

    public int ListeningPort
    {
      get { return Config.LocalHttpsServerPort; }
    }

    public List<IPlugin> LoadedPlugins
    {
      get { return Config.LoadedPlugins; }
    }

    #endregion


    #region PUBLIC

    public override bool Start(int localServerPort, string certificateFilePath)
    {
      // Initialize general values
      Config.RemoteHostIp = "0.0.0.0";
//this.pluginCalls = new Lib.PluginCalls();

// Load all plugins
//this.LoadAllPlugins();

      // Start listener
      serverCertificate2 = new X509Certificate2(certificateFilePath, string.Empty);
      this.tcpListener = new TcpListener(this.ListeningIpInterface, localServerPort);

      Logging.Instance.LogMessage("TcpListener", ProxyProtocol.Undefined, Loglevel.Info, "HTTPS reverse proxy server started on port {0}", localServerPort, Path.GetFileName(certificateFilePath));

      try
      {
        this.tcpListener.Start();
      }
      catch (Exception ex)
      {
        Logging.Instance.LogMessage("TcpListener", ProxyProtocol.Undefined, Loglevel.Error, "ProxyServer.Start(EXCEPTION): {0}", ex.Message);
        return false;
      }

      this.tcpListenerThread = new Thread(new ParameterizedThreadStart(HandleHttpsClient));
      this.tcpListenerThread.Start(this.tcpListener);

      return true;
    }


    public override void Stop()
    {
      this.tcpListener.Stop();

      // Wait for cRemoteSocket to finish processing current connections...
      if (this.tcpListenerThread != null && this.tcpListenerThread.IsAlive)
      {
        this.tcpListenerThread.Abort();
        this.tcpListenerThread.Join();
      }

      // Unload loaded plugins
//this.UnloadAllPlugins();
    }


    public void LoadPlugin(string pluginFileFullPath)
    {
      Assembly pluginAssembly;

      if ((pluginAssembly = Assembly.LoadFile(pluginFileFullPath)) == null)
      {
        throw new Exception("The plugin file could not be loaded");
      }

      try
      {
        string fileName = Path.GetFileName(pluginFileFullPath);
        fileName = Path.GetFileNameWithoutExtension(fileName);

        string pluginName = string.Format("HttpReverseProxy.Plugin.{0}.{0}", fileName);
        Type objType = pluginAssembly.GetType(pluginName, false, false);
        object tmpPluginObj = Activator.CreateInstance(objType, true);

        if (!(tmpPluginObj is HttpReverseProxyLib.Interface.IPlugin))
        {
          throw new Exception("The plugin file does not support the required plugin interface");
        }

        IPlugin tmpPlugin = (IPlugin)tmpPluginObj;
        if (Config.LoadedPlugins.Find(elem => elem.Config.Name == tmpPlugin.Config.Name) != null)
        {
          throw new Exception("This plugin was loaded already");
        }

        tmpPlugin.OnLoad(this);
      }
      catch (Exception ex)
      {
        Console.WriteLine("An error occurred while loading HTTPS plugin file \"{0}\": {1}\r\n{2}", Path.GetFileName(pluginFileFullPath), ex.Message, ex.StackTrace);
      }
    }

    #endregion


    #region PRIVATE

    private static void HandleHttpsClient(object tcpListenerObj)
    {
      TcpListener tcpListener = (TcpListener)tcpListenerObj;
      try
      {
        while (true)
        {
          Logging.Instance.LogMessage("TcpListener", ProxyProtocol.Undefined, Loglevel.Debug, "Waiting for incoming HTTPS request");
          TcpClient tcpClient = tcpListener.AcceptTcpClient();
          tcpClient.NoDelay = true;

          while (!ThreadPool.QueueUserWorkItem(new WaitCallback(HttpsReverseProxy.InitiateHttpsClientRequestProcessing), tcpClient))
          {
            ;
          }
        }
      }
      catch (ThreadAbortException taex)
      {
        Console.WriteLine("HandleHttpsClient(ThreadAbortException): {0}", taex.Message);
      }
      catch (SocketException sex)
      {
        Console.WriteLine("HandleHttpsClient(SocketException): {0}", sex.Message);
      }
      catch (Exception ex)
      {
        Console.WriteLine("HandleHttpsClient(Exception): {0}", ex.Message);
      }
    }


    private static void InitiateHttpsClientRequestProcessing(object clientTcpObj)
    {
      TcpClient tcpClient = (TcpClient)clientTcpObj;
      string clientIp = string.Empty;
      string clientPort = string.Empty;
      string clientMac = string.Empty;
      RequestObj requestObj = new RequestObj(Config.DefaultRemoteHost, ProxyProtocol.Https);

      // Determine tcpClient IP and MAC address.
      try
      {
        Logging.Instance.LogMessage("TcpListener", ProxyProtocol.Https, Loglevel.Debug, "InitiateHttpsClientRequestProcessing(): New HTTPS request initiated");
        string[] splitter = tcpClient.Client.RemoteEndPoint.ToString().Split(new char[] { ':' });
        clientIp = splitter[0];
        clientPort = splitter[1];
      }
      catch (Exception ex)
      {
        Console.WriteLine("InitiateHttpsClientRequestProcessing(Exception): {0}", ex.Message);
      }

      try
      {
        clientMac = Lib.Common.GetMacFromNetworkComputer(clientIp);
      }
      catch (Exception)
      {
        clientMac = "00:00:00:00:00:00";
      }

      requestObj.SrcMac = clientMac;
      requestObj.SrcIp = clientIp;
      requestObj.SrcPort = clientPort;
      requestObj.TcpClientConnection = tcpClient;

      // Open tcpClient system's data clientStream
      try
      {
        SslStream sslStream = new SslStream(requestObj.TcpClientConnection.GetStream(), false, new RemoteCertificateValidationCallback(remoteCertificateValidation));
        sslStream.AuthenticateAsServer(serverCertificate2, false, SslProtocols.Tls | SslProtocols.Ssl3, false);

        requestObj.ClientRequestObj.ClientBinaryReader = new MyBinaryReader(requestObj.ProxyProtocol, sslStream, 8192, Encoding.UTF8, requestObj.Id);
        requestObj.ClientRequestObj.ClientBinaryWriter = new BinaryWriter(sslStream);

        RequestHandlerHttp requestHandler = new RequestHandlerHttp(requestObj);
        requestHandler.ProcessClientRequest();
      }
      catch (Exception ex)
      {
        Logging.Instance.LogMessage(requestObj.Id, requestObj.ProxyProtocol, Loglevel.Debug, "ProxyServer.InitiateHttpsClientRequestProcessing(EXCEPTION): {0}\r\n{1}", ex.Message, ex.GetType().ToString());

        if (ex.InnerException is Exception)
        {
          Logging.Instance.LogMessage(requestObj.Id, requestObj.ProxyProtocol, Loglevel.Debug, "ProxyServer.InitiateHttpsClientRequestProcessing(INNEREXCEPTION): {0}, {1}", ex.InnerException.Message, ex.GetType().ToString());
        }
      }
      finally
      {
        if (requestObj.ClientRequestObj.ClientBinaryReader != null)
        {
          requestObj.ClientRequestObj.ClientBinaryReader.Close();
          Logging.Instance.LogMessage(requestObj.Id, requestObj.ProxyProtocol, Loglevel.Debug, "ProxyServer.InitiateHttpsClientRequestProcessing(): ClientBinaryReader.Close()");
        }

        if (requestObj.ClientRequestObj.ClientBinaryWriter != null)
        {
          requestObj.ClientRequestObj.ClientBinaryWriter.Close();
          Logging.Instance.LogMessage(requestObj.Id, requestObj.ProxyProtocol, Loglevel.Debug, "ProxyServer.InitiateHttpsClientRequestProcessing(): ClientBinaryWriter.Close()");
        }

        if (requestObj.ServerRequestHandler != null)
        {
          requestObj.ServerRequestHandler.CloseServerConnection();
          Logging.Instance.LogMessage(requestObj.Id, requestObj.ProxyProtocol, Loglevel.Debug, "ProxyServer.InitiateHttpsClientRequestProcessing(): ServerRequestHandler.CloseServerConnection())");
        }

        if (requestObj.TcpClientConnection != null)
        {
          requestObj.TcpClientConnection.Close();
          Logging.Instance.LogMessage(requestObj.Id, requestObj.ProxyProtocol, Loglevel.Debug, "ProxyServer.InitiateHttpsClientRequestProcessing(): TcpClientConnection.Close()");
        }
      }
    }


    /// <summary>
    ///
    /// </summary>
    private void LoadAllPlugins()
    {
      string pluginsPath = Path.Combine(Directory.GetCurrentDirectory(), "plugins");
      string[] pluginDirs;

      if (!Directory.Exists(pluginsPath))
      {
        return;
      }

      pluginDirs = Directory.GetDirectories(pluginsPath);

      // Iterate through all plugin directories
      foreach (string tmpPluginDir in pluginDirs)
      {
        string[] pluginFiles = Directory.GetFiles(tmpPluginDir, "*.dll");

        // Load all plugin files, instantiate an object and initialize plugin.
        foreach (string pluginFileFullPath in pluginFiles)
        {
          try
          {
            this.LoadPlugin(pluginFileFullPath);
          }
          catch (Exception ex)
          {
            Console.WriteLine("An error occurred while loading the plugin \"{0}\": {1}", Path.GetFileNameWithoutExtension(pluginFileFullPath), ex.Message);
          }
        }
      }
    }


    private void UnloadAllPlugins()
    {
      List<IPlugin> tmpPluginList = new List<IPlugin>();
      tmpPluginList.AddRange(Config.LoadedPlugins);

      foreach(IPlugin tmpPlugin in tmpPluginList)
      {
        tmpPlugin.OnUnload();
        Config.LoadedPlugins.Remove(tmpPlugin);
      }
    }
    
    #endregion


    #region SSL debugging methods (copied from MSDN)

    static void DisplaySecurityLevel(SslStream stream)
    {
      Console.WriteLine("Cipher: {0} strength {1}", stream.CipherAlgorithm, stream.CipherStrength);
      Console.WriteLine("Hash: {0} strength {1}", stream.HashAlgorithm, stream.HashStrength);
      Console.WriteLine("Key exchange: {0} strength {1}", stream.KeyExchangeAlgorithm, stream.KeyExchangeStrength);
      Console.WriteLine("Protocol: {0}", stream.SslProtocol);
    }


    static void DisplaySecurityServices(SslStream stream)
    {
      Console.WriteLine("Is authenticated: {0} as server? {1}", stream.IsAuthenticated, stream.IsServer);
      Console.WriteLine("IsSigned: {0}", stream.IsSigned);
      Console.WriteLine("Is Encrypted: {0}", stream.IsEncrypted);
    }


    static void DisplayStreamProperties(SslStream stream)
    {
      Console.WriteLine("Can read: {0}, write {1}", stream.CanRead, stream.CanWrite);
      Console.WriteLine("Can timeout: {0}", stream.CanTimeout);
    }


    static void DisplayCertificateInformation(SslStream stream)
    {
      Console.WriteLine("Certificate revocation list checked: {0}", stream.CheckCertRevocationStatus);

      X509Certificate localCertificate = stream.LocalCertificate;
      if (stream.LocalCertificate != null)
      {
        Console.WriteLine("Local cert was issued to {0} and is valid from {1} until {2}.",
            localCertificate.Subject,
            localCertificate.GetEffectiveDateString(),
            localCertificate.GetExpirationDateString());
      }
      else
      {
        Console.WriteLine("Local certificate is null.");
      }
      // Display the properties of the client's certificate.
      X509Certificate remoteCertificate = stream.RemoteCertificate;
      if (stream.RemoteCertificate != null)
      {
        Console.WriteLine("Remote cert was issued to {0} and is valid from {1} until {2}.",
            remoteCertificate.Subject,
            remoteCertificate.GetEffectiveDateString(),
            remoteCertificate.GetExpirationDateString());
      }
      else
      {
        Console.WriteLine("Remote certificate is null.");
      }
    }

    #endregion


    #region INTERFACE: IPluginHost

    /// <summary>
    ///
    /// </summary>
    /// <param name="pluginData"></param>
    public void RegisterPlugin(IPlugin pluginData)
    {
      if (pluginData != null)
      {
        lock (Config.LoadedPlugins)
        {
          List<IPlugin> foundPlugins = Config.LoadedPlugins.FindAll(elem => elem.Config.Name == pluginData.Config.Name);
          if (foundPlugins == null || foundPlugins.Count <= 0)
          {
            Config.AddNewPlugin(pluginData);
            Logging.Instance.LogMessage("HttpsReverseProxy", ProxyProtocol.Undefined, Loglevel.Info, "Registered plugin \"{0}\"", pluginData.Config.Name);
          }
        }
      }
    }


    public Logging LoggingInst { get { return Logging.Instance; } set { } }

    #endregion

  }
}
