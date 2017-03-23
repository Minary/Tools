namespace HttpReverseProxy.Plugin.InjectCode
{
  using HttpReverseProxy.Plugin.InjectCode.DataTypes;
  using HttpReverseProxyLib;
  using HttpReverseProxyLib.DataTypes.Class;
  using HttpReverseProxyLib.DataTypes.Enum;
  using HttpReverseProxyLib.Exceptions;
  using System.IO;
  using System.Text;
  using System.Text.RegularExpressions;


  public partial class InjectCode
  {

    /// <summary>
    /// 
    /// </summary>
    /// <param name="requestObj"></param>
    /// <param name="dataChunk"></param>
    public void OnServerDataTransfer(RequestObj requestObj, DataChunk dataChunk)
    {
      if(requestObj == null)
      {
        throw new ProxyWarningException("The request object is invalid");
      }

      if(dataChunk == null)
      {
        throw new ProxyWarningException("The request object is invalid");
      }

      if(HttpReverseProxy.Plugin.InjectCode.Config.InjectCodeRecords.Count <= 0)
      {
        return;
      }

      foreach(InjectCodeConfigRecord injectRecord in HttpReverseProxy.Plugin.InjectCode.Config.InjectCodeRecords)
      {
        if (Regex.Match(requestObj.ClientRequestObj.Host, injectRecord.HostRegex, RegexOptions.IgnoreCase).Success == true &&
            Regex.Match(requestObj.ClientRequestObj.RequestLine.Path, injectRecord.PathRegex, RegexOptions.IgnoreCase).Success == true)
        {
          // 2. Decode bytes to UTF8
          string readableData = Encoding.UTF8.GetString(dataChunk.ContentData, 0, dataChunk.ContentDataLength);
          MatchCollection matches = Regex.Matches(readableData, injectRecord.TagRegex);
          if (matches.Count > 0)
          {
            string foundTag = matches[0].Groups[1].Value;
            string foundTagEscaped = Regex.Escape(foundTag);
            string replacementData = injectRecord.InjectionCodeFileContent;

            if (injectRecord.Position == DataTypes.TagPosition.before)
            {
              replacementData = replacementData + foundTag;
            }
            else
            {
              replacementData = foundTag + replacementData;
            }

            readableData = Regex.Replace(readableData, foundTagEscaped, replacementData);
            Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.Info, "InjectCode.OnServerDataTransfer(): Injected code from file {0} {1} the tag {2}. hostPattern={3}, pathPattern={4}",
              Path.GetFileName(injectRecord.InjectionCodeFile), injectRecord.Position, injectRecord.Tag, injectRecord.HostRegex, injectRecord.PathRegex);

            // Write data back to datapacket
            dataChunk.ContentData = Encoding.UTF8.GetBytes(readableData);
            dataChunk.ContentDataLength = dataChunk.ContentData.Length;

            break;
          }
        }
      }

      Logging.Instance.LogMessage(requestObj.Id, ProxyProtocol.Undefined, Loglevel.Debug, "InjectCode.OnServerDataTransfer(): ");
    }
  }
}