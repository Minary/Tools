namespace HttpReverseProxy.Plugin.HostMapping
{
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.DataTypes.Interface;
  using System.IO;
  using HostMappingConfig = HttpReverseProxy.Plugin.HostMapping.Config;


  public partial class HostMapping : IPlugin
  {

    #region MEMBERS

    private PluginProperties pluginProperties = new PluginProperties();
    private Config pluginConfig = new Config();
    private string configurationFileFullPath;

    #endregion


    #region PROPERTIES

    public PluginProperties PluginProperties { get { return this.pluginProperties; } set { } }

    #endregion


    #region PUBLIC

    public HostMapping()
    {
      // Set plugin properties
      this.pluginProperties.Name = HostMappingConfig.PluginName;
      this.pluginProperties.Priority = HostMappingConfig.PluginPriority;
      this.pluginProperties.Version = HostMappingConfig.PluginVersion;
      this.pluginProperties.PluginDirectory = Path.Combine(Directory.GetCurrentDirectory(), "plugins", HostMappingConfig.PluginName);
      this.pluginProperties.IsActive = true;
      this.pluginProperties.SupportedProtocols = ProxyProtocol.Http | ProxyProtocol.Https;
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
