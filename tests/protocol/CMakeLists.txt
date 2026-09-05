# Protocol tests
add_executable(test_topic_persist test_topic_persist.c)
add_test(NAME TopicPersistence COMMAND test_topic_persist)
