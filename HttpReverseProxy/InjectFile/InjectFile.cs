namespace HttpReverseProxy.Plugin.InjectFile
{
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.DataTypes.Interface;
  using System.Collections.Generic;
  using System.IO;
  using InjectFileConfig = HttpReverseProxy.Plugin.InjectFile.Config;


  public partial class InjectFile : IPlugin
  {

    #region MEMBERS

    private PluginProperties pluginProperties;
    private string configurationFileFullPath = string.Empty;
    private Dictionary<string, string> injectFileHostPathPair = new Dictionary<string, string>();
    private Config pluginConfig = new Config();

    #endregion


    #region PROPERTIES

    public PluginProperties PluginProperties { get { return this.pluginProperties; } set { } }

    #endregion


    #region PUBLIC

    /// <summary>
    /// 
    /// </summary>
    public InjectFile()
    {
      this.pluginProperties = new PluginProperties()
      {
        Name = InjectFileConfig.PluginName,
        Priority = InjectFileConfig.PluginPriority,
        Version = InjectFileConfig.PluginVersion,
        PluginDirectory = Path.Combine(Directory.GetCurrentDirectory(), "plugins", InjectFileConfig.PluginName),
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
