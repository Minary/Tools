namespace HttpReverseProxy.ToClient.InjectCode
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;


  public class NonChunked
  {

    #region MEMBER

    private RequestObj requestObj;

    #endregion


    #region PUBLIC

    public NonChunked(RequestObj requestObj)
    {
      this.requestObj = requestObj;
    }


    public void InjectIntoNonChunkedTransfer(PluginInstruction pluginInstruction)
    {
      // Add the injected file size to the current Content-Length header value
      this.requestObj.ServerResponseObj.ContentLength = this.requestObj.ServerResponseObj.ContentLength + pluginInstruction.InstructionParameters.DataDict["data"].Length;
      this.requestObj.ServerResponseObj.ResponseHeaders.Remove("Content-Length");
      this.requestObj.ServerResponseObj.ResponseHeaders.Add("Content-Length", new System.Collections.Generic.List<string>() { this.requestObj.ServerResponseObj.ContentLength.ToString() });

      // 5.6 Determine whether response content type must be processed
      bool mustBeProcessed = false; // this.IsServerResponseDataProcessable();

      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpReverseProxy.InjectIntoNonChunkedTransfer(): SERVER RESPONSE : {0}PROCESS", (mustBeProcessed ? string.Empty : "DONT "));

      this.requestObj.ServerRequestHandler.ForwardStatusLineS2C(this.requestObj.ServerResponseObj.StatusLine);
      this.requestObj.ServerRequestHandler.ForwardHeadersS2C(this.requestObj.ServerResponseObj.ResponseHeaders, this.requestObj.ServerResponseObj.StatusLine.NewlineBytes);
      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpReverseProxy.InjectIntoNonChunkedTransfer(): Headers and terminating empty line ({0}) sent", this.requestObj.ServerResponseObj.StatusLine.NewlineType);

this.requestObj.ServerResponseObj.NoTransferredBytes = this.requestObj.ServerRequestHandler.RelayNonChunkedAndInjectDataS2C(pluginInstruction, mustBeProcessed);

      string redirectLocation = this.requestObj.ServerResponseObj.ResponseHeaders.ContainsKey("Location") ? "/" + this.requestObj.ServerResponseObj.ResponseHeaders["Location"][0] : string.Empty;
      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Info, "HttpReverseProxy.InjectIntoNonChunkedTransfer(): {0}{1}, {2}, {3} bytes", this.requestObj.ServerResponseObj.StatusLine.StatusCode, redirectLocation, this.requestObj.ProxyDataTransmissionModeS2C, this.requestObj.ServerResponseObj.NoTransferredBytes);
      Logging.Instance.LogMessage(this.requestObj.Id, this.requestObj.ProxyProtocol, Loglevel.Debug, "HttpReverseProxy.InjectIntoNonChunkedTransfer(): DONE! All data transferred to client");
    }

    #endregion

  }
}
