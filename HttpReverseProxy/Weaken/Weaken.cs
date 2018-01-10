namespace HttpReverseProxy.Plugin.Weaken
{
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.DataTypes.Interface;
  using System.IO;
  using WeakenConfig = HttpReverseProxy.Plugin.Weaken.Config;


  public partial class Weaken : IPlugin
  {

    #region MEMBERS

    private PluginProperties pluginProperties;

    #endregion


    #region PUBLIC

    public Weaken()
    {
      this.pluginProperties = new PluginProperties()
      {
        Name = WeakenConfig.PluginName,
        Priority = WeakenConfig.PluginPriority,
        Version = WeakenConfig.PluginVersion,
        PluginDirectory = Path.Combine(Directory.GetCurrentDirectory(), "plugins", WeakenConfig.PluginName),
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
