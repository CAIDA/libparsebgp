add_executable(parsebgp_tool_parsebgp parsebgp.c)
set_target_properties(parsebgp_tool_parsebgp PROPERTIES
  C_STANDARD 99
  OUTPUT_NAME parsebgp
)
target_link_libraries(parsebgp_tool_parsebgp parsebgp)
