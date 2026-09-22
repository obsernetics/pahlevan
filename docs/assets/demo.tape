# demo.tape - charmbracelet/vhs script for Pahlevan's intro demo.
# Render with:  vhs docs/assets/demo.tape   (produces docs/assets/demo.gif)
#
# Nothing is typed into the terminal except commands. Narration would be a
# comment line the viewer has to read while the output they came for scrolls
# past, so the output does the explaining instead.
#
# It is the console and nothing else: apply a policy, then run `pahlevan`. The
# screens are rendered by pkg/tui into docs/assets/console, and a test fails if
# they stop matching what the console draws, so the recording cannot show a
# screen the tool does not produce.

Output docs/assets/demo.gif

Set Shell "bash"
Set FontSize 20
Set Width 1200
Set Height 820
Set Padding 24
Set Margin 12
Set BorderRadius 10
Set Theme "Catppuccin Mocha"
Set TypingSpeed 22ms
Set PlaybackSpeed 1.0

Hide
Type "source docs/assets/demo.sh; clear" Enter
Show

Type "kubectl apply -f app-policy.yaml"
Enter
Sleep 1200ms

Type "pahlevan"
Enter
Sleep 20s
