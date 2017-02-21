namespace HttpReverseProxyLib.DataTypes
{
  using HttpReverseProxyLib.DataTypes.Class;
  using System.Collections.Generic;


  public class PluginInstruction
  {

    #region MEMBERS

    private Instruction instruction;
    private InstructionParams instructionParameters;

    #endregion


    #region PROPERTIES

    public Instruction Instruction { get { return this.instruction; } set { this.instruction = value; } }

    public InstructionParams InstructionParameters { get { return this.instructionParameters; } set { this.instructionParameters = value; } }

    #endregion


    #region PUBLIC

    /// <summary>
    /// Initializes a new instance of the <see cref="PluginInstruction"/> class.
    ///
    /// </summary>
    /// <param name="instruction"></param>
    /// <param name="url"></param>
    /// <param name="status"></param>
    /// <param name="data"></param>
    /// <param name="httpHeaders"></param>
    public PluginInstruction(Instruction instruction, string url, string status, string data, List<string> httpHeaders)
    {
      this.instruction = instruction;
      this.instructionParameters = new InstructionParams();

      this.instructionParameters.Url = url;
      this.instructionParameters.Status = status;
      this.instructionParameters.Data = data;
      this.instructionParameters.HttpHeaders = httpHeaders;
    }


    /// <summary>
    /// Initializes a new instance of the <see cref="PluginInstruction"/> class.
    ///
    /// </summary>
    public PluginInstruction()
    {
      this.instruction = Instruction.DoNothing;
      this.instructionParameters = new InstructionParams();
      this.instructionParameters.Url = string.Empty;
      this.instructionParameters.Status = string.Empty;
      this.instructionParameters.Data = string.Empty;
      this.instructionParameters.HttpHeaders = new List<string>();
    }

    #endregion

  }
}
