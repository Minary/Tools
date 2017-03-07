namespace HttpReverseProxy.Plugin.HostMapping
{
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.Exceptions;


  public partial class HostMapping
  {

    /// <summary>
    /// 
    /// </summary>
    /// <param name="requestObj"></param>
    /// <param name="dataChunk"></param>
    public void OnServerDataTransfer(RequestObj requestObj, DataChunk dataChunk)
    {
      if (requestObj == null)
      {
        throw new ProxyWarningException("The request object is invalid");
      }

      if (requestObj.ServerResponseObj == null)
      {
        throw new ProxyWarningException("The meta data object is invalid");
      }

      if (dataChunk == null)
      {
        throw new ProxyWarningException("The data packet is invalid");
      }

      if (string.IsNullOrEmpty(requestObj.ServerResponseObj.ContentTypeEncoding.ContentType))
      {
        throw new ProxyWarningException("The server response content type is invalid");
      }

    }
  }
}