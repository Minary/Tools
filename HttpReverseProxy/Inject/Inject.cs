namespace HttpReverseProxy.Plugin.Inject
{
  using System.Collections.Generic;
  using HttpReverseProxyLib.Interface;


  public partial class Inject : IPlugin
  {

    #region MEMBERS

    private PluginProperties pluginProperties;
    private Dictionary<string, Dictionary<string, HttpReverseProxy.Plugin.Inject.DataTypes.InjectType>> injectHostPathPair;
    private Config pluginConfig = new Config();
    private string configurationFileFullPath;

    #endregion


    #region PROPERTIES

    public PluginProperties PluginProperties { get { return this.pluginProperties; } set { this.pluginProperties = value; } }

    public string ConfigurationFileFullPath { get { return this.configurationFileFullPath; } set { } }

    #endregion


    #region PUBLIC

    public Inject()
    {
      // Host->Path->type->redirect_resource
      this.injectHostPathPair = new Dictionary<string, Dictionary<string, DataTypes.InjectType>>();
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
