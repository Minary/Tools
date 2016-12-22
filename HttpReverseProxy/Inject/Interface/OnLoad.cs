namespace HttpReverseProxy.Plugin.Inject
{
  using System;
  using System.IO;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Exceptions;
  using HttpReverseProxyLib.Interface;
  using InjectConfig = HttpReverseProxy.Plugin.Inject.Config;


  public partial class Inject
  {

    /// <summary>
    ///
    /// </summary>
    /// <param name="pluginHost"></param>
    public void OnLoad(IPluginHost pluginHost)
    {
      // Set plugin properties
      this.pluginProperties = new PluginProperties()
      {
        Name = InjectConfig.PluginName,
        Priority = InjectConfig.PluginPriority,
        Version = InjectConfig.PluginVersion,
        PluginDirectory = Path.Combine(Directory.GetCurrentDirectory(), "plugins", InjectConfig.PluginName),
        PluginHost = pluginHost,
        IsActive = true,
      };

      // Parse configuration file
      this.configurationFileFullPath = Path.Combine(this.pluginProperties.PluginDirectory, InjectConfig.ConfigFileName);
      if (string.IsNullOrEmpty(this.configurationFileFullPath))
      {
        return;
      }

      try
      {
        this.pluginConfig.ParseConfigurationFile(this.configurationFileFullPath);
        this.pluginProperties.PluginHost.LoggingInst.LogMessage("Inject", ProxyProtocol.Undefined, Loglevel.INFO, "Inject.OnLoad(): Loaded {0} configuration records", InjectConfig.InjectRecords.Count);
      }
      catch (System.IO.FileNotFoundException)
      {
        string tmpConfigFile = Path.GetFileName(this.configurationFileFullPath);
        this.pluginProperties.PluginHost.LoggingInst.LogMessage("Inject", ProxyProtocol.Undefined, Loglevel.INFO, "Inject.OnLoad(): Config file \"...{0}\" does not exist", tmpConfigFile);
      }
      catch (ProxyErrorException peex)
      {
        this.pluginProperties.PluginHost.LoggingInst.LogMessage("Inject", ProxyProtocol.Undefined, Loglevel.INFO, "Inject.OnLoad(): {0}", peex.Message);
      }
      catch (Exception ex)
      {
        this.pluginProperties.PluginHost.LoggingInst.LogMessage("Inject", ProxyProtocol.Undefined, Loglevel.INFO, "Inject.OnLoad(EXCEPTION): {0}", ex.Message);
      }

      this.pluginProperties.PluginHost.RegisterPlugin(this);
    }
  }
}
