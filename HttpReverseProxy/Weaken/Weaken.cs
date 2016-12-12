namespace HttpReverseProxy.Plugin.Weaken
{
  using HttpReverseProxyLib.Interface;

  public partial class Weaken : IPlugin
  {

    #region MEMBERS

    private PluginProperties pluginProperties;
    private Config weakenConfig;

    #endregion


    #region PROPERTIES

    public PluginProperties PluginProperties { get { return this.pluginProperties; } set { this.pluginProperties = value; } }

    #endregion


    #region PUBLIC

    public Weaken()
    {
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
