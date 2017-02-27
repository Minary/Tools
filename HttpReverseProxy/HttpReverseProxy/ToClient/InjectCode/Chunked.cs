namespace HttpReverseProxy.ToClient.InjectCode
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;


  public class Chunked
  {

    #region MEMBER

    private RequestObj requestObj;

    #endregion


    #region PUBLIC

    public Chunked(RequestObj requestObj)
    {
      this.requestObj = requestObj;
    }


    public void InjectIntoChunkedTransfer(PluginInstruction pluginInstruction)
    {
      // 5.6 Determine whether response content type must be processed
      bool mustBeProcessed = false; // this.IsServerResponseDataProcessable();
      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpReverseProxy.InjectIntoChunkedTransfer(): SERVER RESPONSE : {0}PROCESS", (mustBeProcessed ? string.Empty : "DONT "));

      this.requestObj.ServerRequestHandler.ForwardStatusLineS2C(this.requestObj.ServerResponseObj.StatusLine);
      this.requestObj.ServerRequestHandler.ForwardHeadersS2C(this.requestObj.ServerResponseObj.ResponseHeaders, this.requestObj.ServerResponseObj.StatusLine.NewlineBytes);
      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpReverseProxy.InjectIntoChunkedTransfer(): Headers and terminating empty line ({0}) sent", this.requestObj.ServerResponseObj.StatusLine.NewlineType);

      this.requestObj.ServerResponseObj.NoTransferredBytes = this.requestObj.ServerRequestHandler.RelayChunkedAndInjectDataS2C(pluginInstruction, mustBeProcessed);

      string redirectLocation = this.requestObj.ServerResponseObj.ResponseHeaders.ContainsKey("Location") ? "/" + this.requestObj.ServerResponseObj.ResponseHeaders["Location"][0] : string.Empty;
      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Info, "HttpReverseProxy.InjectIntoChunkedTransfer(): {0}{1}, {2}, {3} bytes", this.requestObj.ServerResponseObj.StatusLine.StatusCode, redirectLocation, this.requestObj.ProxyDataTransmissionModeS2C, this.requestObj.ServerResponseObj.NoTransferredBytes);
      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpReverseProxy.InjectIntoChunkedTransfer(): DONE! All data transferred to client");
    }

    #endregion

  }
}
