namespace HttpReverseProxy.Plugin.SslStrip
{
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Interface;
  using System;
  using System.IO;
  using SslStripConfig = HttpReverseProxy.Plugin.SslStrip.Config;


  public partial class SslStrip
  {

    /// <summary>
    ///
    /// </summary>
    /// <returns></returns>
    public void OnLoad(IPluginHost pluginHost)
    {
      // Set plugin properties
      this.pluginProperties.PluginHost = pluginHost;

      // Parse configuration file
      this.configurationFileFullPath = Path.Combine(this.pluginProperties.PluginDirectory, SslStripConfig.ConfigFileName);
      if (string.IsNullOrEmpty(this.configurationFileFullPath))
      {
        return;
      }

      try
      {
        this.pluginConfig.ParseConfigurationFile(this.configurationFileFullPath);
        this.pluginProperties.PluginHost.LoggingInst.LogMessage("SslStrip", ProxyProtocol.Undefined, Loglevel.Info, "SslStrip.OnLoad(): Loaded {0} content type(s)", Plugin.SslStrip.Config.SearchPatterns.Count);

        foreach (string contentType in Plugin.SslStrip.Config.SearchPatterns.Keys)
        {
          this.pluginProperties.PluginHost.LoggingInst.LogMessage("SslStrip", ProxyProtocol.Undefined, Loglevel.Info, "SslStrip.OnLoad(): Number patterns for content type \"{0}\": {1}", contentType, Plugin.SslStrip.Config.SearchPatterns[contentType].Count);

          foreach (string pattern in Plugin.SslStrip.Config.SearchPatterns[contentType])
          {
            this.pluginProperties.PluginHost.LoggingInst.LogMessage("SslStrip", ProxyProtocol.Undefined, Loglevel.Info, "SslStrip.OnLoad(): Pattern for content type \"{0}\": {1}", contentType, pattern);
          }
        }
      }
      catch (System.IO.FileNotFoundException)
      {
        string tmpConfigFile = Path.GetFileName(this.configurationFileFullPath);
        this.pluginProperties.PluginHost.LoggingInst.LogMessage("SslStrip", ProxyProtocol.Undefined, Loglevel.Info, "SslStrip.OnLoad(): Config file \"...{0}\" does not exist", tmpConfigFile);
      }
      catch (Exception ex)
      {
        this.pluginProperties.PluginHost.LoggingInst.LogMessage("SslStrip", ProxyProtocol.Undefined, Loglevel.Info, "SslStrip.OnLoad(EXCEPTION): {0}", ex.Message);
      }

      this.pluginProperties.PluginHost.RegisterPlugin(this);
    }
  }
}
