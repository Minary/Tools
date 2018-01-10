namespace HttpReverseProxy.Plugin.SslStrip
{
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.Exceptions;
  using System.Collections.Concurrent;


  public partial class SslStrip
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

      if (Plugin.SslStrip.Config.SearchPatterns.ContainsKey(requestObj.ServerResponseObj.ContentTypeEncoding.ContentType) == false)
      {
        return;
      }


      // 1. The content type is right.
      // Iterate through all configured tags and locate
      // them in the server data
      ConcurrentDictionary<string, string> foundHttpsTags = new ConcurrentDictionary<string, string>();
      ConcurrentDictionary<string, string> cacheUrlMapping = new ConcurrentDictionary<string, string>();
      string strippedData = string.Empty;

      this.SslStrippedData = dataChunk.DataEncoding.GetString(dataChunk.ContentData, 0, dataChunk.ContentDataLength);

      // If the "ssl strip"data buffer is null/empty return
      // as there is nothing to do with an empty buffer.
      if (string.IsNullOrEmpty(this.SslStrippedData))
      {
        return;
      }

      this.LocateAllTags(this.SslStrippedData, Plugin.SslStrip.Config.SearchPatterns[requestObj.ServerResponseObj.ContentTypeEncoding.ContentType], foundHttpsTags, cacheUrlMapping);

      // If there were no relevant tags found return.
      if (foundHttpsTags == null || foundHttpsTags.Count <= 0)
      {
        return;
      }

      // Replace previously determined tags by the according replacement tag
      this.SslStrippedData = this.ReplaceRelevantTags(requestObj, this.SslStrippedData, foundHttpsTags);

      // Encode content back to the charset the server reported (or default encoding)
      dataChunk.ContentData = requestObj.ServerResponseObj.ContentTypeEncoding.ContentCharsetEncoding.GetBytes(this.SslStrippedData);
      dataChunk.ContentDataLength = dataChunk.ContentData.Length;

      // Keep SSL stripped URLs in cache
      foreach (string tmpKey in cacheUrlMapping.Keys)
      {
        if (this.cacheSslStrip.SslStripCache.ContainsKey(tmpKey) == false)
        {
          this.cacheSslStrip.AddElement(requestObj.Id, tmpKey, cacheUrlMapping[tmpKey]);
        }
      }
    }
  }
}