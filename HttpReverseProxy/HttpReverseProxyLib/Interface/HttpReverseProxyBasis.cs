namespace HttpReverseProxyLib
{
  using System;
  using System.IO;
  using System.Text.RegularExpressions;


  public abstract class HttpReverseProxyBasis
  {

    #region PUBLIC

    public string CreateCertificate(string certificateHost)
    {
      string certificateFileName = Regex.Replace(certificateHost, @"[^\d\w_]", "_");
      string certificateOutputPath = string.Format("{0}.pfx", certificateFileName);
      string certificateFullPath = Path.Combine(Directory.GetCurrentDirectory(), certificateOutputPath);
      DateTime validityStartDate = DateTime.Now.AddDays(-1);
      DateTime validityEndDate = DateTime.Now.AddYears(5);

      Console.WriteLine("Creating new certificate for host {0}", certificateHost);

      // Delete certificate file if it already exists
      if (File.Exists(certificateFullPath))
      {
        Console.WriteLine("Certificate file \"{0}\" already exists. You have to (re)move the file in order to create a new certificate.", certificateOutputPath);
        return certificateFullPath;
      }

      // Create certificate
      NativeWindowsLib.Crypto.Crypto.CreateNewCertificate(certificateOutputPath, certificateHost, validityStartDate, validityEndDate);
      Console.WriteLine("Certificate created successfully.");
      Console.WriteLine("Certificate file: {0}", certificateOutputPath);
      Console.WriteLine("Certificate validity start: {0}", validityStartDate);
      Console.WriteLine("Certificate validity end: {0}", validityEndDate);

      return certificateFullPath;
    }

    #endregion


    #region ABSTRACT METHODS

    public abstract bool Start(int localServerPort, string certificatePath);

    public abstract void Stop();

    #endregion

  }
}
