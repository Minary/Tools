namespace HttpReverseProxy.Http
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes;
  using HttpReverseProxyLib.Interface;
  using System;
  using System.Collections.Generic;
  using System.IO;
  using System.Net;
  using System.Net.Sockets;
  using System.Reflection;
  using System.Text;
  using System.Threading;


  public sealed class HttpReverseProxy : IPluginHost
  {

    #region MEMBERS

    private static readonly HttpReverseProxy ReverseProxyServer = new HttpReverseProxy();
    private TcpListener tcpListener;
    private Thread tcpListenerThread;
    private Lib.PluginCalls pluginCalls;

    #endregion


    #region PROPERTIES

    public static HttpReverseProxy Server
    {
      get { return ReverseProxyServer; }
    }

    public IPAddress ListeningIpInterface
    {
      get { return IPAddress.Any; }
    }

    public int ListeningPort
    {
      get { return Config.LocalHttpServerPort; }
    }

    public List<IPlugin> LoadedPlugins
    {
      get { return Config.LoadedPlugins; }
    }

    #endregion


    #region PUBLIC METHODS

    /// <summary>
    ///
    /// </summary>
    /// <returns></returns>
    public bool Start(int localServerPort)
    {
      // Initialize general values
      Config.RemoteHostIp = "0.0.0.0";
      this.pluginCalls = new Lib.PluginCalls();

      // Load all plugins
      this.LoadAllPlugins();

      // Start listener
      this.tcpListener = new TcpListener(this.ListeningIpInterface, localServerPort);

      try
      {
        this.tcpListener.Start();
      }
      catch (Exception ex)
      {
        Logging.Instance.LogMessage("TcpListener", Logging.Level.ERROR, "ProxyServer.Start(EXCEPTION): {0}", ex.Message);
        return false;
      }

      this.tcpListenerThread = new Thread(new ParameterizedThreadStart(HandleHttpClient));
      this.tcpListenerThread.Start(this.tcpListener);

      return true;
    }

 
    public void Stop()
    {
      this.tcpListener.Stop();

      // Wait for cRemoteSocket to finish processing current connections...
      if (this.tcpListenerThread != null && this.tcpListenerThread.IsAlive)
      {
        this.tcpListenerThread.Abort();
        this.tcpListenerThread.Join();
      }

      // Unload loaded plugins
      this.UnloadAllPlugins();
    }

    #endregion


    #region PRIVATE METHODS

    private static void HandleHttpClient(object tcpListenerObj)
    {
      TcpListener tcpListener = (TcpListener)tcpListenerObj;
      try
      {
        while (true)
        {
          TcpClient tcpClient = tcpListener.AcceptTcpClient();
          tcpClient.NoDelay = true;

          while (!ThreadPool.QueueUserWorkItem(new WaitCallback(HttpReverseProxy.InitiateClientRequestProcessing), tcpClient))
          {
            ;
          }
        }
      }
      catch (ThreadAbortException taex)
      {
        Console.WriteLine("HandleHttpClient(ThreadAbortException): {0}", taex.Message);
      }
      catch (SocketException sex)
      {
        Console.WriteLine("HandleHttpClient(SocketException): {0}", sex.Message);
      }
      catch (Exception ex)
      {
        Console.WriteLine("HandleHttpClient(Exception): {0}", ex.Message);
      }
    }

    
    private static void InitiateClientRequestProcessing(object clientTcpObj)
    {
      TcpClient tcpClient = (TcpClient)clientTcpObj;
      string clientIp = string.Empty;
      string clientPort = string.Empty;
      string clientMac = string.Empty;
      RequestObj requestObj = new RequestObj(Config.DefaultRemoteHost);

      //// Determine tcpClient IP and MAC address.
      try
      {
        string[] splitter = tcpClient.Client.RemoteEndPoint.ToString().Split(new char[] { ':' });
        clientIp = splitter[0];
        clientPort = splitter[1];
      }
      catch (Exception ex)
      {
        Console.WriteLine("InitiateClientRequestProcessing(Exception): {0}", ex.Message);
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

      // Open tcpClient system's data lClientStream
      try
      {
        requestObj.ClientRequestObj.ClientBinaryReader = new MyBinaryReader(requestObj.TcpClientConnection.GetStream(), 8192, Encoding.UTF8, requestObj.Id);
        requestObj.ClientRequestObj.ClientBinaryWriter = new BinaryWriter(requestObj.TcpClientConnection.GetStream());

        RequestHandlerHttp requestHandler = new RequestHandlerHttp(requestObj);
        requestHandler.ProcessClientRequest();
      }
      catch (Exception ex)
      {
        Logging.Instance.LogMessage(requestObj.Id, Logging.Level.DEBUG, "ProxyServer.InitiateClientRequestProcessing(EXCEPTION): {0}", ex.Message);
      }
      finally
      {
        if (requestObj.ClientRequestObj.ClientBinaryReader != null)
        {
          requestObj.ClientRequestObj.ClientBinaryReader.Close();
          Logging.Instance.LogMessage(requestObj.Id, Logging.Level.DEBUG, "ProxyServer.InitiateClientRequestProcessing(): ClientBinaryReader.Close()");
        }

        if (requestObj.ClientRequestObj.ClientBinaryWriter != null)
        {
          requestObj.ClientRequestObj.ClientBinaryWriter.Close();
          Logging.Instance.LogMessage(requestObj.Id, Logging.Level.DEBUG, "ProxyServer.InitiateClientRequestProcessing(): ClientBinaryWriter.Close()");
        }

        if (requestObj.ServerRequestHandler != null)
        {
          requestObj.ServerRequestHandler.CloseServerConnection();
          Logging.Instance.LogMessage(requestObj.Id, Logging.Level.DEBUG, "ProxyServer.InitiateClientRequestProcessing(): ServerRequestHandler.CloseServerConnection())");
        }

        if (requestObj.TcpClientConnection != null)
        {
          requestObj.TcpClientConnection.Close();
          Logging.Instance.LogMessage(requestObj.Id, Logging.Level.DEBUG, "ProxyServer.InitiateClientRequestProcessing(): TcpClientConnection.Close()");
        }
      }
    }


    /// <summary>
    ///
    /// </summary>
    private void LoadAllPlugins()
    {
      Assembly pluginAssembly;
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
          if ((pluginAssembly = Assembly.LoadFile(pluginFileFullPath)) == null)
          {
            continue;
          }

          try
          {
            string fileName = Path.GetFileName(pluginFileFullPath);
            fileName = Path.GetFileNameWithoutExtension(fileName);

            string pluginName = string.Format("HttpReverseProxy.Plugin.{0}.{0}", fileName);
            Type objType = pluginAssembly.GetType(pluginName, false, false);
            object tmpPluginObj = Activator.CreateInstance(objType);

            if (!(tmpPluginObj is HttpReverseProxyLib.Interface.IPlugin))
            {
              continue;
            }

            IPlugin tmpPlugin = (IPlugin)tmpPluginObj;
            tmpPlugin.OnLoad(this);
          }
          catch (Exception ex)
          {
            Console.WriteLine("Error occurred while loading plugin file \"{0}\": {1}\r\n{2}", pluginFileFullPath, ex.Message, ex.StackTrace);
          }
        }
      }
    }


    private void UnloadAllPlugins()
    {
      List<IPlugin> tmpPluginList = new List<IPlugin>();
      tmpPluginList.AddRange(Config.LoadedPlugins);

      foreach (IPlugin tmpPlugin in tmpPluginList)
      {
        tmpPlugin.OnUnload();
        Config.LoadedPlugins.Remove(tmpPlugin);
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
            Logging.Instance.LogMessage("HttpReverseProxy", Logging.Level.INFO, "Registered plugin \"{0}\"", pluginData.Config.Name);
          }
        }
      }
    }


    public Logging LoggingInst { get { return Logging.Instance; }  set { } }

    #endregion

  }
}
