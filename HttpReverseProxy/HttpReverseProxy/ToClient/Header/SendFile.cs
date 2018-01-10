using System;
using System.Globalization;
using System.IO;


namespace HttpReverseProxy.ToClient.Header
{

  public class SendFile
  {

    #region MEMBERS

    private static string statusLine = "HTTP/1.1 200 OK";
    private static string server = "Server: Apache";
    private static string date = string.Empty;
    private static string contentLength = string.Empty;
    private static string contentType = "Content-Type: application/octet-stream";
    private static string contentDisposition = string.Empty;
    private static string connection = "Connection: close";

    #endregion


    #region PUBLIC

    public static string GetHeader(string injectFilePath, int fileContentLength, string serverNewLine)
    {
      var tmpDate = DateTime.Now.ToString("ddd, dd MMM yyyy HH:mm:ss", CultureInfo.InvariantCulture);
      date = $"Date: {tmpDate}";
      contentLength = $"Content-Length: {fileContentLength}";
      contentDisposition = $@"Content-Disposition: attachment; filename=""{Path.GetFileName(injectFilePath)}""";

      string header = string.Join(
                                  serverNewLine,
                                  statusLine,
                                  server,
                                  date,
                                  contentLength,
                                  contentType,
                                  contentDisposition,
                                  connection,
                                  serverNewLine);

      return header;
    }

    #endregion

  }
}
