namespace HttpReverseProxyLib.DataTypes.Interface
{
  public interface IPluginHost
  {

    Logging LoggingInst { get; set; }

    void RegisterPlugin(IPlugin pluginData);
  }
}
