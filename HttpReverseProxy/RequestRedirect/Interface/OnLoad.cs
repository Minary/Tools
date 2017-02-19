namespace HttpReverseProxy.Plugin.RequestRedirect
{
  using System;
  using System.IO;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Exceptions;
  using HttpReverseProxyLib.Interface;


  public partial class RequestRedirect
  {

    /// <summary>
    ///
    /// </summary>
    /// <param name="pluginHost"></param>
    public void OnLoad(IPluginHost pluginHost)
    {
      // Set plugin properties
      this.pluginProperties.PluginHost = pluginHost;

      // Parse configuration file
      this.configurationFileFullPath = Path.Combine(this.pluginProperties.PluginDirectory, Plugin.RequestRedirect.Config.ConfigFileName);
      if (string.IsNullOrEmpty(this.configurationFileFullPath))
      {
        return;
      }

      try
      {
        this.pluginConfig.ParseConfigurationFile(this.configurationFileFullPath);
        this.pluginProperties.PluginHost.LoggingInst.LogMessage("RequestRedirect", ProxyProtocol.Undefined, Loglevel.Info, "RequestRedirect.OnLoad(): Loaded {0} configuration records", Plugin.RequestRedirect.Config.RequestRedirectRecords.Count);
      }
      catch (System.IO.FileNotFoundException)
      {
        string tmpConfigFile = Path.GetFileName(this.configurationFileFullPath);
        this.pluginProperties.PluginHost.LoggingInst.LogMessage("RequestRedirect", ProxyProtocol.Undefined, Loglevel.Info, "RequestRedirect.OnLoad(): Config file \"...{0}\" does not exist", tmpConfigFile);
      }
      catch (ProxyErrorException peex)
      {
        this.pluginProperties.PluginHost.LoggingInst.LogMessage("RequestRedirect", ProxyProtocol.Undefined, Loglevel.Info, "RequestRedirect.OnLoad(): {0}", peex.Message);
      }
      catch (Exception ex)
      {
        this.pluginProperties.PluginHost.LoggingInst.LogMessage("RequestRedirect", ProxyProtocol.Undefined, Loglevel.Info, "RequestRedirect.OnLoad(EXCEPTION): {0}", ex.Message);
      }

      this.pluginProperties.PluginHost.RegisterPlugin(this);
    }
  }
}
