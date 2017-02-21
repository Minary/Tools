namespace HttpReverseProxyLib.DataTypes.Class
{
  using System.Collections.Generic;


  public class InstructionParams
  {

    #region MEMBERS

    private Instruction instruction;
    private string url;
    private string status;
    private string statusDescription;
    private string data;
    private List<string> httpHeaders;

    #endregion


    #region PROPERTIES

    public Instruction Instruction { get { return this.instruction; } set { this.instruction = value; } }

    public string Url { get { return this.url; } set { this.url = value; } }

    public string Status { get { return this.status; } set { this.status = value; } }

    public string StatusDescription { get { return this.statusDescription; } set { this.statusDescription = value; } }

    public string Data { get { return this.data; } set { this.data = value; } }

    public List<string> HttpHeaders { get { return this.httpHeaders; } set { this.httpHeaders = value; } }

    #endregion

  }
}
