namespace HttpReverseProxyLib.Interface
{
  public interface IPluginHost
  {

    Logging LoggingInst { get; set; }

    void RegisterPlugin(IPlugin pluginData);
  }
}
