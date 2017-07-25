namespace HttpReverseProxy.Plugin.InjectCode
{
  using System;
  using System.IO;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Exceptions;
  using HttpReverseProxyLib.DataTypes.Interface;


  public partial class InjectCode
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
      this.configurationFileFullPath = Path.Combine(this.pluginProperties.PluginDirectory, Plugin.InjectCode.Config.ConfigFileName);

      if (string.IsNullOrEmpty(this.configurationFileFullPath))
      {
        return;
      }

      try
      {
        this.pluginConfig.ParseConfigurationFile(this.configurationFileFullPath);
        this.pluginProperties.PluginHost.LoggingInst.LogMessage("InjectCode", ProxyProtocol.Undefined, Loglevel.Info, "InjectCode.OnLoad(): Loaded {0} configuration record(s)", Plugin.InjectCode.Config.InjectCodeRecords?.Count ?? 0);
      }
      catch (FileNotFoundException)
      {
        string tmpConfigFile = Path.GetFileName(this.configurationFileFullPath);
        this.pluginProperties.PluginHost.LoggingInst.LogMessage("InjectCode", ProxyProtocol.Undefined, Loglevel.Info, "InjectCode.OnLoad(): Config file \"...\\{0}\" does not exist", tmpConfigFile);
      }
      catch (ProxyErrorException peex)
      {
        this.pluginProperties.PluginHost.LoggingInst.LogMessage("InjectCode", ProxyProtocol.Undefined, Loglevel.Info, "InjectCode.OnLoad(): {0}", peex.Message);
      }
      catch (Exception ex)
      {
        this.pluginProperties.PluginHost.LoggingInst.LogMessage("InjectCode", ProxyProtocol.Undefined, Loglevel.Info, "InjectCode.OnLoad(EXCEPTION): {0}", ex.Message);
      }

      this.pluginProperties.PluginHost.RegisterPlugin(this);
    }
  }
}
