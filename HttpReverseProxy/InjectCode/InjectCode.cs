namespace HttpReverseProxy.Plugin.InjectCode
{
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.DataTypes.Interface;
  using System.Collections.Generic;
  using System.IO;
  using InjectCodeConfig = HttpReverseProxy.Plugin.InjectCode.Config;


  public partial class InjectCode : IPlugin
  {

    #region MEMBERS

    private string configurationFileFullPath = string.Empty;
    private PluginProperties pluginProperties = new PluginProperties();
    private Dictionary<string, string> injectFileHostPathPair = new Dictionary<string, string>();
    private Config pluginConfig = new Config();

    #endregion


    #region PUBLIC

    /// <summary>
    /// 
    /// </summary>
    public InjectCode()
    {
      this.pluginProperties = new PluginProperties()
      {
        Name = InjectCodeConfig.PluginName,
        Priority = InjectCodeConfig.PluginPriority,
        Version = InjectCodeConfig.PluginVersion,
        PluginDirectory = Path.Combine(Directory.GetCurrentDirectory(), "plugins", InjectCodeConfig.PluginName),
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
