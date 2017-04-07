namespace HttpReverseProxy.Plugin.SslStrip
{
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;
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

      this.sslStrippedData = dataChunk.DataEncoding.GetString(dataChunk.ContentData, 0, dataChunk.ContentDataLength);

      // If the "ssl strip"data buffer is null/empty return
      // as there is nothing to do with an empty buffer.
      if (string.IsNullOrEmpty(this.sslStrippedData))
      {
        return;
      }

      this.LocateAllTags(this.sslStrippedData, Plugin.SslStrip.Config.SearchPatterns[requestObj.ServerResponseObj.ContentTypeEncoding.ContentType], foundHttpsTags, cacheUrlMapping);

      // If there were no relevant tags found return.
      if (foundHttpsTags == null || foundHttpsTags.Count <= 0)
      {
        return;
      }

      // Replace previously determined tags by the according replacement tag
      this.sslStrippedData = this.ReplaceRelevantTags(requestObj, this.sslStrippedData, foundHttpsTags);

      // Encode content back to the charset the server reported (or default encoding)
      dataChunk.ContentData = requestObj.ServerResponseObj.ContentTypeEncoding.ContentCharsetEncoding.GetBytes(this.sslStrippedData);
      dataChunk.ContentDataLength = dataChunk.ContentData.Length;

      // Keep SSL stripped URLs in cache
      foreach (string tmpKey in cacheUrlMapping.Keys)
      {
        if (Cache.CacheSslStrip.Instance.SslStripCache.ContainsKey(tmpKey) == false)
        {
          Cache.CacheSslStrip.Instance.AddElement(requestObj.Id, tmpKey, cacheUrlMapping[tmpKey]);
        }
      }
    }
  }
}