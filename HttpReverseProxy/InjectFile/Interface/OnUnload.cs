namespace HttpReverseProxy.Plugin.InjectFile
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Enum;


  public partial class InjectFile
  {

    /// <summary>
    ///
    /// </summary>
    public void OnUnload()
    {
      Logging.Instance.LogMessage("InjectFile", ProxyProtocol.Undefined, Loglevel.Debug, "InjectFile.OnUnload(): ");
    }
  }
}
