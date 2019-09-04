namespace HttpReverseProxyLib
{
  using System;
  using System.IO;
  using System.Text.RegularExpressions;


  public abstract class HttpReverseProxyBasis
  {
    
    #region ABSTRACT METHODS

    public abstract bool Start(int localServerPort, string certificatePath);

    public abstract void Stop();

    #endregion

  }
}
