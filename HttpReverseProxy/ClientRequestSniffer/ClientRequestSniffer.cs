namespace HttpReverseProxy.Plugin.ClientRequestSniffer
{
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Interface;
  using System;
  using System.IO;
  using System.IO.Pipes;
  using System.Threading.Tasks;
  using ClientSnifferConfig = HttpReverseProxy.Plugin.ClientRequestSniffer.Config;


  public partial class ClientRequestSniffer : IPlugin
  {

    #region MEMBERS

    private PluginProperties pluginProperties;
    private NamedPipeClientStream pipeClient = null;
    private StreamWriter pipeWriter = null;

    #endregion


    #region PROPERTIES

    public PluginProperties PluginProperties { get { return this.pluginProperties; } set { this.pluginProperties = value; } }

    #endregion


    #region PUBLIC
    
    public ClientRequestSniffer()
    {
      // Set plugin properties
      this.pluginProperties = new PluginProperties()
      {
        Name = ClientSnifferConfig.PluginName,
        Priority = ClientSnifferConfig.PluginPriority,
        Version = ClientSnifferConfig.PluginVersion,
        PluginDirectory = Path.Combine(Directory.GetCurrentDirectory(), "plugins", ClientSnifferConfig.PluginName),
        IsActive = true,
        SupportedProtocols = ProxyProtocol.Http | ProxyProtocol.Https
      };
    }


    /// <summary>
    ///
    /// </summary>
    /// <param name="requestObj"></param>
    private void SendClientRequestDataToPipe(RequestObj requestObj)
    {
      // 2. Send request/response data to pipe/GUI
      string pipeData = string.Format("TCP||{0}||{1}||{2}||{3}||{4}||{5}\r\n",
                                      requestObj.SrcMac,
                                      requestObj.SrcIp,
                                      requestObj.SrcPort,
                                      requestObj.ClientRequestObj.Host,
                                      80,
                                      requestObj.HttpLogData);
      Task.Run(() => this.WriteToPipe(requestObj, pipeData));
      this.pluginProperties.PluginHost.LoggingInst.LogMessage(requestObj.Id, requestObj.ProxyProtocol, Loglevel.Debug, "ClientRequestSniffer.SendClientRequestDataToPipe(): Sending data to attack service pipe: {0} ...", pipeData.Trim().Substring(0, 40));
    }


    /// <summary>
    /// 
    /// </summary>
    /// <param name="requestObj"></param>
    /// <param name="pipeData"></param>
    /// <returns></returns>
    public bool WriteToPipe(RequestObj requestObj, string pipeData)
    {
      bool retVal = false;

      // Create Pipe
      try
      {
        if (this.pipeClient == null)
        {
          this.pipeClient = new NamedPipeClientStream(ClientSnifferConfig.DATA_OUTPUT_PIPE_NAME);
        }

        if (!this.pipeClient.IsConnected)
        {
          this.pipeClient.Connect(500);
        }

        if (this.pipeClient != null && this.pipeClient.IsConnected)
        {
          if (this.pipeWriter == null)
          {
            this.pipeWriter = new StreamWriter(this.pipeClient);
            this.pipeWriter.AutoFlush = true;
          }

          if (this.pipeWriter != null && this.pipeClient.IsConnected && this.pipeClient.CanWrite)
          {
            if (pipeData.Length > 0)
            {
              string tmpBuffer = pipeData.Trim();
              this.pipeWriter.WriteLine(tmpBuffer);
            }

            retVal = true;
          }
          else
          {
            this.pipeClient = null;
            this.pipeWriter = null;
          }
        }
      }
      catch (System.TimeoutException tex)
      {
        this.pluginProperties.PluginHost.LoggingInst.LogMessage(requestObj.Id, requestObj.ProxyProtocol, Loglevel.Warning, "ClientRequestSniffer.WriteToPipe(TimeOutException): {0}", tex.Message);
      }
      catch (Exception ex)
      {
        this.pluginProperties.PluginHost.LoggingInst.LogMessage(requestObj.Id, requestObj.ProxyProtocol, Loglevel.Warning, "ClientRequestSniffer.WriteToPipe(Exception): {0}", ex.Message);
      }

      return retVal;
    }

    #endregion


    #region INTERFACE IMPLEMENTATION: Properties

    public PluginProperties Config { get { return this.pluginProperties; } set { this.pluginProperties = value; } }

    #endregion


    #region INTERFACE IMPLEMENTATION: IComparable

    public int CompareTo(IPlugin other)
    {
      if (other == null)
      {
        return 1;
      }

      if (this.Config.Priority > other.Config.Priority)
      {
        return 1;
      }
      else if (this.Config.Priority < other.Config.Priority)
      {
        return -1;
      }
      else
      {
        return 0;
      }
    }

    #endregion


  }
}
