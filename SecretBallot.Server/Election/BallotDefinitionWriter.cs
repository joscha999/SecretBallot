using System.Text;
using System.Text.Json;

namespace SecretBallot.Server.Election;

public static class BallotDefinitionWriter {
    public const string NoneOfThemOption = "keinen der Kandidierenden";

    public static string Write(Guid id, BallotDraft draft) {
        var options = OptionsFor(draft);
        var noneIndex = draft.Type == BallotType.Single ? options.Count - 1 : -1;

        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream)) {
            writer.WriteStartObject();
            writer.WriteString("id", id.ToString());
            writer.WriteString("title", draft.Title.Trim());
            writer.WriteString("type", TypeName(draft.Type));
            writer.WriteStartArray("options");
            foreach (var option in options)
                writer.WriteStringValue(option);
            writer.WriteEndArray();
            writer.WriteNumber("seats", draft.Type == BallotType.Approval ? draft.Seats : 1);
            writer.WriteNumber("noneOptionIndex", noneIndex);
            writer.WriteEndObject();
        }
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    public static List<string> OptionsFor(BallotDraft draft) {
        if (draft.Type == BallotType.YesNo)
            return new List<string> { "Ja", "Nein" };

        var options = draft.Options.Select(o => o.Trim()).ToList();
        if (draft.Type == BallotType.Single)
            options.Add(NoneOfThemOption);
        return options;
    }

    private static string TypeName(BallotType type) {
        return type switch {
            BallotType.Approval => "approval",
            BallotType.Single => "single",
            _ => "yesno"
        };
    }
}
