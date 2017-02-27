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
    private string data2;
    private Dictionary<string, string> dataDict = new Dictionary<string, string>();
    private List<string> httpHeaders;

    #endregion


    #region PROPERTIES

    public Instruction Instruction { get { return this.instruction; } set { this.instruction = value; } }

    public string Url { get { return this.url; } set { this.url = value; } }

    public string Status { get { return this.status; } set { this.status = value; } }

    public string StatusDescription { get { return this.statusDescription; } set { this.statusDescription = value; } }

    public string Data { get { return this.data; } set { this.data = value; } }

    public string Data2 { get { return this.data2; } set { this.data2 = value; } }

    public Dictionary<string, string> DataDict { get { return this.dataDict; } set { this.dataDict = value; } }

    public List<string> HttpHeaders { get { return this.httpHeaders; } set { this.httpHeaders = value; } }

    #endregion

  }
}
