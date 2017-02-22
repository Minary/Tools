namespace HttpReverseProxy.Plugin.HostMapping
{
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Interface;
  using System.IO;
  using HostMappingConfig = HttpReverseProxy.Plugin.HostMapping.Config;


  public partial class HostMapping : IPlugin
  {

    #region MEMBERS

    private PluginProperties pluginProperties;
    private Config pluginConfig = new Config();
    private string configurationFileFullPath;

    #endregion


    #region PROPERTIES

    public Config PluginConfig { get { return this.pluginConfig; } set { } }

    #endregion


    #region PUBLIC

    public HostMapping()
    {
      // Set plugin properties
      this.pluginProperties = new PluginProperties()
      {
        Name = HostMappingConfig.PluginName,
        Priority = HostMappingConfig.PluginPriority,
        Version = HostMappingConfig.PluginVersion,
        PluginDirectory = Path.Combine(Directory.GetCurrentDirectory(), "plugins", HostMappingConfig.PluginName),
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
