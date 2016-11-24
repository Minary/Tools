namespace HttpReverseProxy.Plugin.HostMapping
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes;
  using HttpReverseProxyLib.Interface;
  using System;
  using System.Collections.Concurrent;
  using System.Collections.Generic;
  using System.Text.RegularExpressions;


  public partial class HostMapping : HttpReverseProxyLib.Interface.IPlugin
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
      //this.sslStrippedData = string.Empty;
      //this.sslStrippedHosts = new Dictionary<string, bool>();
      //this.sslStrippedUrls = new Dictionary<string, string>();
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
