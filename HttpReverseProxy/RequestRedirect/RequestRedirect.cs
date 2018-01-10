namespace HttpReverseProxy.Plugin.RequestRedirect
{
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.DataTypes.Interface;
  using System.Collections.Generic;
  using System.IO;
  using RequestRedirectConfig = HttpReverseProxy.Plugin.RequestRedirect.Config;


  public partial class RequestRedirect : IPlugin
  {

    #region MEMBERS

    private PluginProperties pluginProperties;
    private string configurationFileFullPath = string.Empty;
    private Dictionary<string, string> injectHostPathPair = new Dictionary<string, string>();
    private Config pluginConfig = new Config();

    #endregion
    

    #region PUBLIC

    /// <summary>
    /// 
    /// </summary>
    public RequestRedirect()
    {
      this.pluginProperties = new PluginProperties()
      {
        Name = RequestRedirectConfig.PluginName,
        Priority = RequestRedirectConfig.PluginPriority,
        Version = RequestRedirectConfig.PluginVersion,
        PluginDirectory = Path.Combine(Directory.GetCurrentDirectory(), "plugins", RequestRedirectConfig.PluginName),
        IsActive = true,
        SupportedProtocols = ProxyProtocol.Http | ProxyProtocol.Https
      };
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

