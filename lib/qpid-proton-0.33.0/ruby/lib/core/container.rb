# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.


require 'thread'
require 'set'
require_relative 'listener'
require_relative 'work_queue'

module Qpid::Proton
  public

  # An AMQP container manages a set of {Listener}s and {Connection}s which
  # contain {#Sender} and {#Receiver} links to transfer messages.  Usually, each
  # AMQP client or server process has a single container for all of its
  # connections and links.
  #
  # One or more threads can call {#run}, events generated by all the listeners and
  # connections will be dispatched in the {#run} threads.
  class Container
    include TimeCompare

    # Error raised if the container is used after {#stop} has been called.
    class StoppedError < Qpid::Proton::StoppedError
      def initialize() super("container has been stopped"); end
    end

    # Create a new Container
    # @overload initialize(id=nil)
    #   @param id [String,Symbol] A unique ID for this container, use random UUID if nil.
    #
    # @overload initialize(handler=nil, id=nil)
    #  @param id [String,Symbol] A unique ID for this container, use random UUID if nil.
    #  @param handler [MessagingHandler] Optional default handler for connections
    #   that do not have their own handler (see {#connect} and {#listen})
    #
    #   *Note*: For multi-threaded code, it is recommended to use a separate
    #   handler instance for each connection, as a shared handler may be called
    #   concurrently.
    #
    def initialize(*args)
      @handler, @id = nil
      case args.size
      when 2 then @handler, @id = args
      when 1 then
        @id = String.try_convert(args[0]) || (args[0].to_s if args[0].is_a? Symbol)
        @handler = args[0] unless @id
      when 0 then
      else raise ArgumentError, "wrong number of arguments (given #{args.size}, expected 0..2"
      end
      # Use an empty messaging adapter to give default behaviour if there's no global handler.
      @adapter = Handler::Adapter.adapt(@handler) || Handler::MessagingAdapter.new(nil)
      @id = (@id || SecureRandom.uuid).freeze

      # Threading and implementation notes: see comment on #run_one
      @work = Queue.new
      @work << :start
      @work << :select
      @wake = SelectWaker.new   # Wakes #run thread in IO.select
      @auto_stop = true         # Stop when @active drops to 0
      @work_queue = WorkQueue.new(self)  # work scheduled by other threads for :select context

      # Following instance variables protected by lock
      @lock = Mutex.new
      @active = 0               # All active tasks, in @selectable, @work or being processed
      @selectable = Set.new     # Tasks ready to block in IO.select
      @running = 0              # Count of #run threads
      @stopped = false          # #stop called
      @stop_err = nil           # Optional error to pass to tasks, from #stop
      @panic = nil              # Exception caught in a run thread, to be raised by all run threads
    end

    # @return [MessagingHandler] The container-wide handler
    attr_reader :handler

    # @return [String] unique identifier for this container
    attr_reader :id

    def to_s() "#<#{self.class} id=#{id.inspect}>"; end
    def inspect() to_s; end

    # Auto-stop flag.
    #
    # True (the default) means that the container will stop automatically, as if {#stop}
    # had been called, when the last listener or connection closes.
    #
    # False means {#run} will not return unless {#stop} is called.
    #
    # @return [Bool] auto-stop state
    attr_accessor :auto_stop

    # True if the container has been stopped and can no longer be used.
    # @return [Bool] stopped state
    attr_accessor :stopped

    # Number of threads in {#run}
    # @return [Bool] {#run} thread count
    def running() @lock.synchronize { @running }; end

    # Open an AMQP connection.
    #
    # @param url [String, URI] Open a {TCPSocket} to url.host, url.port.
    # url.scheme must be "amqp" or "amqps", url.scheme.nil? is treated as "amqp"
    # url.user, url.password are used as defaults if opts[:user], opts[:password] are nil
    # @option (see Connection#open)
    # @return [Connection] The new AMQP connection
    def connect(url, opts=nil)
      not_stopped
      url = Qpid::Proton::uri url
      opts ||= {}
      if url.user ||  url.password
        opts[:user] ||= url.user
        opts[:password] ||= url.password
      end
      opts[:ssl_domain] ||= SSLDomain.new(SSLDomain::MODE_CLIENT) if url.scheme == "amqps"
      connect_io(TCPSocket.new(url.host, url.port), opts)
    end

    # Open an AMQP protocol connection on an existing {IO} object
    # @param io [IO] An existing {IO} object, e.g. a {TCPSocket}
    # @option (see Connection#open)
    def connect_io(io, opts=nil)
      not_stopped
      cd = connection_driver(io, opts)
      cd.connection.open()
      add(cd)
      cd.connection
    end

    # Listen for incoming AMQP connections
    #
    # @param url [String,URI] Listen on host:port of the AMQP URL
    # @param handler [Listener::Handler] A {Listener::Handler} object that will be called
    # with events for this listener and can generate a new set of options for each one.
    # @return [Listener] The AMQP listener.
    #
    def listen(url, handler=Listener::Handler.new)
      not_stopped
      url = Qpid::Proton::uri url
      # TODO aconway 2017-11-01: amqps, SSL
      listen_io(TCPServer.new(url.host, url.port), handler)
    end

    # Listen for incoming AMQP connections on an existing server socket.
    # @param io A server socket, for example a {TCPServer}
    # @param handler [Listener::Handler] Handler for events from this listener
    #
    def listen_io(io, handler=Listener::Handler.new)
      not_stopped
      l = ListenTask.new(io, handler, self)
      add(l)
      l.listener
    end

    # Run the container: wait for IO activity, dispatch events to handlers.
    #
    # *Multi-threaading* : More than one thread can call {#run} concurrently,
    # the container will use all {#run} threads as a thread pool. Calls to
    # {MessagingHandler} or {Listener::Handler} methods are serialized for each
    # connection or listener. See {WorkQueue} for coordinating with other
    # threads.
    #
    # *Exceptions*: If any handler method raises an exception it will stop the
    # container, and the exception will be raised by all calls to {#run}. For
    # single threaded code this is often desirable. Multi-threaded server
    # applications should normally rescue exceptions in the handler and deal
    # with them in another way: logging, closing the connection with an error
    # condition, signalling another thread etc.
    #
    # @return [void] Returns when the container stops, see {#stop} and {#auto_stop}
    #
    # @raise [StoppedError] If the container has already been stopped when {#run} was called.
    #
    # @raise [Exception] If any {MessagingHandler} or {Listener::Handler} managed by
    #   the container raises an exception, that exception will be raised by {#run}
    #
    def run
      @lock.synchronize do
        @running += 1        # Note: ensure clause below will decrement @running
        raise StoppedError if @stopped
      end
      while task = @work.pop
        run_one(task, Time.now)
      end
      @lock.synchronize { raise @panic if @panic }
    ensure
      @lock.synchronize do
        if (@running -= 1) > 0
          work_wake nil         # Signal the next thread
        else
          # This is the last thread, no need to do maybe_panic around this final handler call.
          @adapter.on_container_stop(self) if @adapter.respond_to? :on_container_stop
        end
      end
    end

    # Stop the container.
    #
    # Close all listeners and abort all connections without doing AMQP protocol close.
    #
    # {#stop} returns immediately, calls to {#run} will return when all activity
    # is finished.
    #
    # The container can no longer be used, using a stopped container raises
    # {StoppedError}.  Create a new container if you want to resume activity.
    #
    # @param error [Condition] Optional error condition passed to
    #  {MessagingHandler#on_transport_error} for each connection and
    #  {Listener::Handler::on_error} for each listener.
    #
    # @param panic [Exception] Optional exception to raise from all calls to run()
    #
    def stop(error=nil, panic=nil)
      @lock.synchronize do
        return if @stopped
        @stop_err = Condition.convert(error)
        @panic = panic
        @stopped = true
        check_stop_lh
        # NOTE: @stopped =>
        # - no new run threads can join
        # - no more select calls after next wakeup
        # - once @active == 0, all threads will be stopped with nil
      end
      wake
    end

    # Get the {WorkQueue} that can be used to schedule code to be run by the container.
    #
    # Note: to run code that affects a {Connection} or it's associated objects,
    # use {Connection#work_queue}
    def work_queue() @work_queue; end

    # (see WorkQueue#schedule)
    def schedule(at, &block) @work_queue.schedule(at, &block) end

    private

    def wake() @wake.wake; end

    class ConnectionTask < Qpid::Proton::HandlerDriver
      include TimeCompare

      def initialize container, io, opts, server=false
        super io, opts[:handler]
        transport.set_server if server
        transport.apply opts
        connection.apply opts
        @work_queue = WorkQueue.new(container)
        connection.instance_variable_set(:@work_queue, @work_queue)
      end
      def next_tick() earliest(super, @work_queue.next_tick); end
      def process(now) @work_queue.process(now); super(); end

      def dispatch              # Intercept dispatch to close work_queue
        super
        @work_queue.close if read_closed? && write_closed?
      end
    end

    class ListenTask < Listener

      def initialize(io, handler, container)
        @io, @handler = io, handler
        @listener = Listener.new(io, container)
        env = ENV['PN_TRACE_EVT']
        if env && ["true", "1", "yes", "on"].include?(env.downcase)
          @log_prefix = "[0x#{object_id.to_s(16)}](PN_LISTENER_"
        else
          @log_prefix = nil
        end
        dispatch(:on_open);
      end

      attr_reader :listener
      def closing?() @listener.instance_variable_get(:@closing); end
      def condition() @listener.instance_variable_get(:@condition); end
      def closed?() @io.closed?; end

      def process
        return if closed?
        unless closing?
          begin
            return @io.accept, dispatch(:on_accept)
          rescue IO::WaitReadable, Errno::EINTR
          rescue StandardError => e
            @listener.close(e)
          end
        end
      ensure
        if closing?
          @io.close rescue nil
          @listener.instance_variable_set(:@closed, true)
          dispatch(:on_error, condition) if condition
          dispatch(:on_close)
        end
      end

      def can_read?() !finished?; end
      def can_write?() false; end
      def finished?() closed?; end

      def dispatch(method, *args)
        # TODO aconway 2017-11-27: better logging
        STDERR.puts "#{@log_prefix}#{([method[3..-1].upcase]+args).join ', '})" if @log_prefix
        @handler.__send__(method, self, *args) if @handler && @handler.respond_to?(method)
      end

      def next_tick() nil; end

      # Close listener and force immediate close of socket
      def close(e=nil)
        @listener.close(e)
        @io.close rescue nil
      end
    end

    # Selectable object that can be used to wake IO.select from another thread
    class SelectWaker
      def initialize
        @rd, @wr = IO.pipe
        @lock = Mutex.new
        @set = false
      end

      def to_io() @rd; end

      def wake
        @lock.synchronize do
          return if @set        # Don't write if already has data
          @set = true
          @wr.write_nonblock('x') rescue nil
        end
      end

      def reset
        @lock.synchronize do
          return unless @set
          @rd.read_nonblock(1) rescue nil
          @set = false
        end
      end

      def close
        @rd.close
        @wr.close
      end
    end

    # Handle a single item from the @work queue, this is the heart of the #run loop.
    # Take one task from @work, process it, and rearm for select
    # Tasks are: ConnectionTask, ListenTask, :start, :select
    # - ConnectionTask/ListenTask have #can_read, #can_write, #next_tick to set up IO.select
    #   and #process to run handlers and process relevant work_queue
    # - nil means exit from the  #run thread exit (handled by #run)
    # - :select does IO.select and processes Container#work_queue
    def run_one(task, now)
      case task

      when :start
        maybe_panic { @adapter.on_container_start(self) } if @adapter.respond_to? :on_container_start

      when :select
        # Compute read/write select sets and minimum next_tick for select timeout
        r, w = [@wake], []
        next_tick = @work_queue.next_tick
        @lock.synchronize do
          @selectable.each do |s|
            r << s if s.can_read?
            w << s if s.can_write?
            next_tick = earliest(s.next_tick, next_tick)
          end
        end

        timeout = ((next_tick > now) ? next_tick - now : 0) if next_tick
        r, w = IO.select(r, w, nil, timeout)
        @wake.reset if r && r.delete(@wake)
        now = Time.now unless timeout == 0 # Update now if we may have blocked

        # selected is a Set to eliminate duplicates between r, w and next_tick due.
        selected = Set.new
        selected.merge(r) if r
        selected.merge(w) if w
        stopped = @lock.synchronize do
          if @stopped           # close everything
            @selectable.each { |s| s.close @stop_err; @work << s }
            @selectable.clear
            @work_queue.close
            @wake.close
          else
            @selectable -= selected # Remove already-selected tasks from @selectable
            # Also select and remove items with next_tick before now
            @selectable.delete_if { |s| before_eq(s.next_tick, now) and selected << s }
          end
          @stopped
        end
        selected.each { |s| @work << s } # Queue up tasks needing #process
        maybe_panic { @work_queue.process(now) } # Process current work queue items
        @work_queue.clear if stopped
        @lock.synchronize { check_stop_lh } if @work_queue.empty?

        @work << :select  unless stopped # Enable next select

      when ConnectionTask then
        maybe_panic { task.process now }
        rearm task

      when ListenTask then
        io, opts = maybe_panic { task.process }
        add(connection_driver(io, opts, true)) if io
        rearm task
      end
    end

    # Rescue any exception raised by the block and stop the container.
    def maybe_panic
      begin
        yield
      rescue Exception => e
        stop(nil, e)
        nil
      end
    end

    # Normally if we add work we need to set a wakeup to ensure a single #run
    # thread doesn't get stuck in select while there is other work on the queue.
    def work_wake(task)
      @work << task
      @wake.wake
    end

    def connection_driver(io, opts=nil, server=false)
      opts ||= {}
      opts[:container] = self
      opts[:handler] ||= @adapter
      ConnectionTask.new(self, io, opts, server)
    end

    # All new tasks are added here
    def add task
      @lock.synchronize do
        @active += 1
        task.close @stop_err if @stopped
      end
      work_wake task
    end

    def rearm task
      @lock.synchronize do
        if task.finished?
          @active -= 1
          check_stop_lh
        elsif @stopped
          task.close @stop_err
          work_wake task
        else
          @selectable << task
        end
      end
      @wake.wake
    end

    def check_stop_lh
      if @active.zero? && (@auto_stop || @stopped) && @work_queue.empty?
        @stopped = true
        work_wake nil          # Signal threads to stop
        true
      end
    end

    def not_stopped() raise StoppedError if @lock.synchronize { @stopped }; end

  end
end
