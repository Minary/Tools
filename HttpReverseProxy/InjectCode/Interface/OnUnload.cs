namespace HttpReverseProxy.Plugin.InjectCode
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Enum;


  public partial class InjectCode
  {

    /// <summary>
    ///
    /// </summary>
    public void OnUnload()
    {
      Logging.Instance.LogMessage("InjectCode", ProxyProtocol.Undefined, Loglevel.Debug, "InjectCode.OnUnload(): ");
    }
  }
}
