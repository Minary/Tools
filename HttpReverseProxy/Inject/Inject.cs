namespace HttpReverseProxy.Plugin.Inject
{
  using HttpReverseProxyLib.Interface;
  using System.Collections.Generic;
  using System.IO;
  using InjectConfig = HttpReverseProxy.Plugin.Inject.Config;


  public partial class Inject : IPlugin
  {

    #region MEMBERS

    private PluginProperties pluginProperties;
    private Dictionary<string, string> injectHostPathPair;
    private Config pluginConfig = new Config();
    private string configurationFileFullPath;

    #endregion


    #region PROPERTIES

    public PluginProperties PluginProperties { get { return this.pluginProperties; } set { this.pluginProperties = value; } }

    public string ConfigurationFileFullPath { get { return this.configurationFileFullPath; } set { } }

    #endregion


    #region PUBLIC

    /// <summary>
    /// 
    /// </summary>
    public Inject()
    {
      this.pluginProperties = new PluginProperties()
      {
        Name = InjectConfig.PluginName,
        Priority = InjectConfig.PluginPriority,
        Version = InjectConfig.PluginVersion,
        PluginDirectory = Path.Combine(Directory.GetCurrentDirectory(), "plugins", InjectConfig.PluginName),
        IsActive = true,
      };

      // Host->Path->type->redirect_resource
      this.injectHostPathPair = new Dictionary<string, string>();
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
